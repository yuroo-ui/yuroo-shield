"""OpenAI-compatible LLM client. Works with MiMo, OpenRouter, OpenAI, llama.cpp."""
from __future__ import annotations

import httpx


class LLMClient:
    def __init__(
        self,
        api_key: str | None,
        base_url: str,
        model: str,
        timeout: float = 60.0,
    ):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._client = httpx.AsyncClient(timeout=timeout)

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def reason(self, prompt: str, system: str | None = None) -> str:
        """Single-turn completion. Returns "" if no API key configured."""
        if not self.enabled:
            return ""
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        r = await self._client.post(
            f"{self._base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={"model": self._model, "messages": msgs, "temperature": 0.2},
        )
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]
