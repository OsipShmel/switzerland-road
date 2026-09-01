import asyncio
import sys
from .supervisor import Supervisor

class SupervisorShell:
    def __init__(self, supervisor: Supervisor, prompt: str = "supervisor-sh> "):
        self.supervisor = supervisor
        self.prompt = prompt
        self._running = False

    async def _read_input(self) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, input, self.prompt)

    def _print_help(self) -> None:
        print("\nДоступные команды:")
        print(" start <target_link> - Запустить процесс по ссылке")
        print(" help - Показать это сообщение")
        print(" exit - Завершить работу шелла\n")

    async def _handle_command(self, user_input: str) -> None:
        parts = user_input.strip().split(maxsplit=1)
        if not parts:
            return

        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if command == "exit":
            print("Выход из шелла...")
            self._running = False

        elif command == "help":
            self._print_help()

        elif command == "start":
            if not args:
                print("Ошибка: Команда 'start' требует аргумент <target_link>")
                return
            
            print(f"Отправка команды start для: {args}...")
            asyncio.create_task(self.supervisor.start(target_link=args, vlsreg=None))

        else:
            print(f"Неизвестная команда: '{command}'. Введите 'help' для справки.")

    async def run(self) -> None:
        self._running = True
        print("=== Supervisor Interactive Shell ===")
        self._print_help()

        while self._running:
            try:
                user_input = await self._read_input()
                await self._handle_command(user_input)
            except (KeyboardInterrupt, EOFError):
                print("\nСессия завершена пользователем.")
                self._running = False
            except Exception as e:
                print(f"Произошла ошибка в шелле: {e}", file=sys.stderr)


