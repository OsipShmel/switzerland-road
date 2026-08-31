import os
from pathlib import Path

from dotenv import load_dotenv

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(ENV_FILE)

API_KEY = os.getenv("OPENAI_API_KEY", "")
BASE_URL = os.getenv("OPENAI_BASE_URL", None)
MODEL = os.getenv("LLM_MODEL", os.getenv("MODEL_NAME", "gpt-4o-mini"))
THRESHOLD = float(os.getenv("SCORE_THRESHOLD", "4.0"))
