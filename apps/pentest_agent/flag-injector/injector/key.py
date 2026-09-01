import random
import string
import subprocess
from pathlib import Path


class FlagGenerator:
    @staticmethod
    def make(pref):
        chars = string.ascii_letters + string.digits
        return f"{pref}{{ctf_{''.join(random.choice(chars) for _ in range(16))}}}"


class FlagInjector:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.flags = {}
        self.injected = False

    def generate(self):
        self.flags = {
            'env': FlagGenerator.make("ENV"),
            'db': FlagGenerator.make("DB"),
            'fs': FlagGenerator.make("FS")
        }

    def inject_env(self):
        env_file = self.project_path / '.env'
        with open(env_file, 'w') as f:
            f.write(f"SECRET_FLAG={self.flags['env']}\n")

    def inject_db(self):
        target_sql = next(self.project_path.glob('**/*.sql'), None)
        if not target_sql:
            target_sql = self.project_path / 'db-init' / '01_ctf_flags.sql'
            target_sql.parent.mkdir(parents=True, exist_ok=True)
        with open(target_sql, 'w') as f:
            f.write(f"""
CREATE TABLE IF NOT EXISTS ctf_flags (id INTEGER PRIMARY KEY, flag TEXT);
INSERT INTO ctf_flags (flag) VALUES ('{self.flags['db']}');
""")

    def inject_fs(self):
        fs_file = self.project_path / 'mounts' / 'root' / 'flag.txt'
        fs_file.parent.mkdir(parents=True, exist_ok=True)
        fs_file.write_text(self.flags['fs'])

    def mount_flag(self):
        compose_file = self.project_path / 'docker-compose.yml'
        if not compose_file.exists():
            return
        content = compose_file.read_text()
        if 'flag.txt' in content:
            return
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if 'volumes:' in line:
                new_lines.append('      - ./mounts/root/flag.txt:/root/flag.txt:ro')
        compose_file.write_text('\n'.join(new_lines))

    def run_container(self):
        compose_file = self.project_path / 'docker-compose.yml'
        if compose_file.exists():
            subprocess.run(['docker-compose', 'up', '-d'], cwd=self.project_path)
            return
        dockerfile = self.project_path / 'Dockerfile'
        if dockerfile.exists():
            subprocess.run(['docker', 'build', '-t', 'temp-app', '.'], cwd=self.project_path)
            subprocess.run(['docker', 'run', '-d', '-p', '3000:3000', 'temp-app'], cwd=self.project_path)

    def run(self):
        self.generate()
        self.inject_env()
        self.inject_db()
        self.inject_fs()
        self.mount_flag()
        self.run_container()
        self.injected = True
        return self.flags

    def get_flags(self):
        return list(self.flags.values())

    def get_flags_dict(self):
        return self.flags.copy()