import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

WORDLIST_DIR = Path.home() / "wordlists" / "SecLists" / "Discovery" / "Web-Content"
RESULTS_DIR = Path(__file__).parent / "results"

LLM_MODEL = "openai/gpt-oss-120b"
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

SCAN_TIMEOUT = 120
MAX_RECURSION_DEPTH = 2
MAX_RECURSE_TARGETS = 3