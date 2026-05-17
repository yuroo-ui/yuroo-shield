"""Runtime configuration loaded from environment."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv(override=False)


@dataclass(frozen=True)
class Settings:
    etherscan_api_key: str
    llm_api_key: str | None
    llm_base_url: str
    llm_model: str
    holder_concentration_threshold: float
    min_holders_safe: int

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key)


def load_settings() -> Settings:
    return Settings(
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY", ""),
        llm_api_key=os.getenv("LLM_API_KEY") or os.getenv("MIMO_API_KEY") or None,
        llm_base_url=os.getenv("LLM_BASE_URL", "https://api.xiaomimimo.com/v1").rstrip("/"),
        llm_model=os.getenv("LLM_MODEL", "mimo-v2.5-pro"),
        holder_concentration_threshold=float(
            os.getenv("HOLDER_CONCENTRATION_THRESHOLD", "0.5")
        ),
        min_holders_safe=int(os.getenv("MIN_HOLDERS_SAFE", "1000")),
    )


# Etherscan v2 chain IDs — single API key, switch via chainid query param.
CHAIN_IDS = {
    "ethereum": 1,
    "bsc": 56,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "base": 8453,
}
