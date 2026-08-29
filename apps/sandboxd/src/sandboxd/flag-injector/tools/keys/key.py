import sys
import random
import string
import subprocess
from pathlib import Path


class FlagGenerator:
    @staticmethod
    def make(pref):
        chars = string.ascii_letters + string.digits
        rand_str = ''.join(random.choice(chars) for _ in range(16))
        return f"{pref}{{ctf_{rand_str}}}"


class Injector:
    def __init__(self, path):
        self.path = Path(path)
        self.flags = {}
    
    def generate(self):
        self.flags = {
            'env': FlagGenerator.make("ENV"),
            'db': FlagGenerator.make("DB"),
            'fs': FlagGenerator.make("FS")
        }
    
    def inject_env(self):
        env_file = self.path / '.env'
        with open(env_file, 'a') as f:
            f.write(f"\nSECRET_FLAG={self.flags['env']}\n")
    
    def inject_db(self):
        sql_files = list(self.path.glob('**/*.sql'))
        if not sql_files:
            init_dir = self.path / 'db-init'
            init_dir.mkdir(exist_ok=True)
            target_sql = init_dir / '01_ctf_flags.sql'
            target_sql.touch()
        else:
            target_sql = sql_files[0]
        
        with open(target_sql, 'a') as f:
            f.write(f"\nCREATE TABLE IF NOT EXISTS ctf_flags (id INTEGER PRIMARY KEY, flag TEXT);\n")
            f.write(f"INSERT INTO ctf_flags (flag) VALUES ('{self.flags['db']}');\n")
    
    def inject_fs(self):
        fs_file = self.path / 'mounts' / 'root' / 'flag.txt'
        fs_file.parent.mkdir(parents=True, exist_ok=True)
        fs_file.write_text(self.flags['fs'])
    
    def run(self):
        self.generate()
        self.inject_env()
        self.inject_db()
        self.inject_fs()
        print(f"ENV: {self.flags['env']}")
        print(f"DB: {self.flags['db']}")
        print(f"FS: {self.flags['fs']}")


class DockerRunner:
    def __init__(self, path):
        self.path = Path(path)
    
    def mount_flag(self):
        compose_file = self.path / 'docker-compose.yml'
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
    
    def run(self):
        compose_file = self.path / 'docker-compose.yml'
        if compose_file.exists():
            subprocess.run(['docker-compose', 'up', '-d'], cwd=self.path)
        else:
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
        print("Использование: python key.py")
        sys.exit(1)
    
    app = App(sys.argv[1])
    app.run()
