import sys
import random
import string
import subprocess
from pathlib import Path


class FlagGenerator:
    @staticmethod
    def make(pref):
        chars = string.ascii_letters + string.digits
        return f"{pref}{{ctf_{''.join(random.choice(chars) for _ in range(16))}}}"


class Injector:
    def __init__(self, path):
        self.path = Path(path)
        self.flags = {}
    
    def generate(self):
        self.flags = {key: FlagGenerator.make(key) for key in ["ENV", "DB", "FS"]}
    
    def inject_env(self):
        env_file = self.path / '.env'
        with open(env_file, 'w') as f:
            f.write(f"SECRET_FLAG={self.flags['env']}\n")
    
    def inject_db(self):
        target_sql = next(self.path.glob('**/*.sql'), None)
        if not target_sql:
            target_sql = self.path / 'db-init' / '01_ctf_flags.sql'
            target_sql.parent.mkdir(exist_ok=True)
        
        with open(target_sql, 'w') as f:
            f.write(f"""
CREATE TABLE IF NOT EXISTS ctf_flags (id INTEGER PRIMARY KEY, flag TEXT);
INSERT INTO ctf_flags (flag) VALUES ('{self.flags['db']}');
""")
    
    def inject_fs(self):
        fs_file = self.path / 'mounts' / 'root' / 'flag.txt'
        fs_file.parent.mkdir(parents=True, exist_ok=True)
        fs_file.write_text(self.flags['fs'])
    
    def run(self):
        self.generate()
        self.inject_env()
        self.inject_db()
        self.inject_fs()
        for key in ['env', 'db', 'fs']:
            print(f"{key.upper()}: {self.flags[key]}")

class DockerRunner:
    def __init__(self, path):
        self.path = Path(path)
    
    def mount_flag(self):
        compose_file = self.path / 'docker-compose.yml'
        if not compose_file.exists() or 'flag.txt' in compose_file.read_text():
            return
        
        lines = compose_file.read_text().split('\n')
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if 'volumes:' in line:
                new_lines.append('      - ./mounts/root/flag.txt:/root/flag.txt:ro')
        compose_file.write_text('\n'.join(new_lines))
    
    def run(self):
        compose_file = self.path / 'docker-compose.yml'
        if compose_file.exists():
            subprocess.run(['docker-compose', 'up', '-d'], cwd=self.path)
            return
        
        dockerfile = self.path / 'Dockerfile'
        if dockerfile.exists():
            subprocess.run(['docker', 'build', '-t', 'temp-app', '.'], cwd=self.path)
            subprocess.run(['docker', 'run', '-d', '-p', '3000:3000', 'temp-app'], cwd=self.path)


class App:
    def __init__(self, path):
        self.path = path
        self.injector = Injector(path)
        self.docker = DockerRunner(path)
    
    def run(self):
        self.injector.run()
        self.docker.mount_flag()
        self.docker.run()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("key.py")
        sys.exit(1)
    
    App(sys.argv[1]).run()