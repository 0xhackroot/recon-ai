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

llm = GroqClient(api_key=GROQ_API_KEY)