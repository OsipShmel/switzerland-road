import subprocess
import json


def run_semgrep(target_dir):
    print("начинаем SAST сканирование")
    cmd = [  # базовое правило sqli
        "semgrep",
        "scan",
        "--config",
        "p/sql-injection",
        "--json",
        "--quiet",
        target_dir,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("ошибка парсинга вывода semgrep")
        return {"results": []}
