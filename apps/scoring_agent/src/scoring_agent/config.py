import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY", "")
BASE_URL = os.getenv("OPENAI_BASE_URL", None)
MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
THRESHOLD = float(os.getenv("SCORE_THRESHOLD", "4.0"))