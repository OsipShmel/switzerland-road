# ... существующие импорты

# Лимиты для AI и LangGraph
import os
MAX_AI_FORMAT_RETRIES = int(os.getenv("PENTEST_MAX_AI_RETRIES", "3"))
LANGGRAPH_RECURSION_LIMIT = int(os.getenv("PENTEST_RECURSION_LIMIT", "10"))

# Таймауты
GATEWAY_TIMEOUT = float(os.getenv("GATEWAY_TIMEOUT", "5.0"))
IAST_TIMEOUT = float(os.getenv("IAST_TIMEOUT", "2.0"))
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "3.0"))

# Максимальное количество ошибок до остановки
MAX_CONSECUTIVE_ERRORS = int(os.getenv("MAX_CONSECUTIVE_ERRORS", "5"))
