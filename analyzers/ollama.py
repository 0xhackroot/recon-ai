import httpx

class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mistral"):
        self.base_url = base_url
        self.model = model

    def generate(self, prompt: str, temperature: float = 0.1) -> str:
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "temperature": temperature,
                "stream": False
            },
            timeout=300
        )
        response.raise_for_status()
        return response.json()["response"]

llm = OllamaClient()