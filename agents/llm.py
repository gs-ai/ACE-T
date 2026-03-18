from __future__ import annotations
from typing import Optional
import subprocess
import json

class OllamaLLM:
    def __init__(self, binary: str, model: str, max_tokens: int = 800, temperature: float = 0.2):
        self.binary = binary
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

    def generate_json(self, system: str, user: str) -> Optional[dict]:
        """
        Calls local 'ollama run <model>' with a constrained JSON-only instruction.
        Returns parsed JSON dict or None.
        """
        prompt = (
            f"{system}\n\n"
            "Return ONLY valid JSON. No markdown. No commentary.\n\n"
            f"{user}"
        )
        try:
            p = subprocess.run(
                [self.binary, "run", self.model],
                input=prompt.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120
            )
            out = p.stdout.decode("utf-8", errors="ignore").strip()
            # attempt to isolate JSON
            start = out.find("{")
            end = out.rfind("}")
            if start >= 0 and end > start:
                out = out[start:end+1]
            return json.loads(out)
        except Exception:
            return None
