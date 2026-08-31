import os

SANDBOXD_GATEWAY_URL: str = os.getenv(
    "SANDBOXD_GATEWAY_URL",
    "http://gateway:9000",
)

TARGET_URL: str = os.getenv(
    "TARGET_URL",
    "http://target:3000",
)

AGENT_PORT: int = int(os.getenv("AGENT_PORT", "8080"))

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL: str = os.getenv(
    "OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M")

MAX_AI_FORMAT_RETRIES: int = int(os.getenv("PENTEST_MAX_AI_RETRIES", "3"))
LANGGRAPH_RECURSION_LIMIT: int = int(
    os.getenv("PENTEST_RECURSION_LIMIT", "10"))

GATEWAY_TIMEOUT: float = float(os.getenv("GATEWAY_TIMEOUT", "5.0"))
IAST_TIMEOUT: float = float(os.getenv("IAST_TIMEOUT", "2.0"))
OLLAMA_TIMEOUT: float = float(os.getenv("OLLAMA_TIMEOUT", "3.0"))

MAX_CONSECUTIVE_ERRORS: int = int(os.getenv("MAX_CONSECUTIVE_ERRORS", "5"))

FALLBACK_ATTACK_PARAM: str = os.getenv("PENTEST_FALLBACK_PARAM", "q")
