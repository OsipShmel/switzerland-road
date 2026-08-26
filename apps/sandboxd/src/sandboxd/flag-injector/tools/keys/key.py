import sys
import random
import string
import subprocess
from pathlib import Path

base_dir = Path(sys.argv[1])

def make_flag(pref):
    chars = string.ascii_letters + string.digits
    rand_str = ''.join(random.choice(chars) for _ in range(16))
    return f"{pref}{{ctf_{rand_str}}}"

flag_env = make_flag("ENV")
flag_db = make_flag("DB")
flag_fs = make_flag("FS")

env_file = base_dir / '.env'
with open(env_file, 'a') as f:
    f.write(f"\nSECRET_FLAG={flag_env}\n")

sql_files = list(base_dir.glob('**/*.sql'))
if len(sql_files) == 0:
    init_dir = base_dir / 'db-init'
    init_dir.mkdir(exist_ok=True)
    target_sql = init_dir / '01_ctf_flags.sql'
    target_sql.touch()
else:
    target_sql = sql_files[0]

with open(target_sql, 'a') as f:
    f.write(f"\nCREATE TABLE IF NOT EXISTS ctf_flags (id INTEGER PRIMARY KEY, flag TEXT);\n")
    f.write(f"INSERT INTO ctf_flags (flag) VALUES ('{flag_db}');\n")

fs_file = base_dir / 'mounts' / 'root' / 'flag.txt'
fs_file.parent.mkdir(parents=True, exist_ok=True)
fs_file.write_text(flag_fs)

compose_file = base_dir / 'docker-compose.sandboxd.yml'
if compose_file.exists():
    content = compose_file.read_text()
    if 'flag.txt' not in content:
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if 'volumes:' in line and '- ./mounts/root/flag.txt:/root/flag.txt:ro' not in content:
                new_lines.append('      - ./mounts/root/flag.txt:/root/flag.txt:ro')
        compose_file.write_text('\n'.join(new_lines))

if compose_file.exists():
    subprocess.run(['docker-compose', 'up', '-d'], cwd=base_dir)
else:
    dockerfile = base_dir / 'Dockerfile'
    if dockerfile.exists():
        subprocess.run(['docker', 'build', '-t', 'temp-app', '.'], cwd=base_dir)
        subprocess.run(['docker', 'run', '-d', '-p', '3000:3000', 'temp-app'], cwd=base_dir)

print(f"ENV: {flag_env}")
print(f"DB: {flag_db}")
print(f"FS: {flag_fs}")