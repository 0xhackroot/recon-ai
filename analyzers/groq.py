import time
import httpx
from config import GROQ_API_KEY, LLM_MODEL

class GroqClient:
    def __init__(self, api_key: str, model: str = LLM_MODEL):
        if not api_key:
            raise ValueError("GROQ_API_KEY not set — check your .env file")
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1"

    def generate(self, prompt: str, temperature: float = 0.1) -> str:
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": temperature
                    },
                    timeout=60
                )
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"]
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt < max_retries - 1:
                    wait_time = 2 ** (attempt + 1) # 2s, 4s, 8s
                    print(f"[!] Groq rate limit hit. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    raise

llm = GroqClient(api_key=GROQ_API_KEY)
