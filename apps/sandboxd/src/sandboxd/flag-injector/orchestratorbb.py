from injector import FlagInjector
from config.settings import DO_INJECT

def run_pipeline(project_path):
    if DO_INJECT:
        injector = FlagInjector(project_path)
        flags = injector.run()
        print(f"Флаги: {flags}")
        return flags
    else:
        print("Инжектор отключён")
        return []

if __name__ == "__main__":
    run_pipeline("bb")