import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # reads .env into environment variables

# Paths
WORDLIST_DIR = Path.home() / "wordlists" / "SecLists" / "Discovery" / "Web-Content"
RESULTS_DIR = Path(__file__).parent / "results"

# LLM
LLM_MODEL = "openai/gpt-oss-120b"
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

# Safety
SCAN_TIMEOUT = 120