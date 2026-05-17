"""Etherscan v2 multichain client.

Docs: https://docs.etherscan.io/etherscan-v2
Single endpoint https://api.etherscan.io/v2/api with chainid query param.
"""
from __future__ import annotations

from typing import Any

import httpx

from .config import CHAIN_IDS

ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"


class EtherscanError(RuntimeError):
    pass


class EtherscanClient:
    def __init__(self, api_key: str, timeout: float = 20.0):
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY is required")
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "EtherscanClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _chain_id(self, chain: str) -> int:
        try:
            return CHAIN_IDS[chain.lower()]
        except KeyError as e:
            raise EtherscanError(
                f"unsupported chain '{chain}'. supported: {list(CHAIN_IDS)}"
            ) from e

    async def _call(self, chain: str, **params: Any) -> Any:
        params = {**params, "chainid": self._chain_id(chain), "apikey": self._api_key}
        r = await self._client.get(ETHERSCAN_V2_BASE, params=params)
        r.raise_for_status()
        data = r.json()
        # Etherscan returns status="1" on success, status="0" on no-result/error.
        # For some endpoints (proxy.eth_*) the shape is JSON-RPC style with "result".
        if "status" in data and data["status"] == "0":
            msg = data.get("message", "")
            # "No transactions found" / "No records found" are legit empty results.
            if msg and "No " in msg:
                return []
            raise EtherscanError(f"{params.get('action')}: {msg or data.get('result')}")
        return data.get("result", data)

    async def get_source_code(self, address: str, chain: str = "ethereum") -> dict:
        result = await self._call(
            chain, module="contract", action="getsourcecode", address=address
        )
        return result[0] if isinstance(result, list) and result else {}

    async def get_contract_abi(self, address: str, chain: str = "ethereum") -> str:
        return await self._call(
            chain, module="contract", action="getabi", address=address
        )

    async def get_token_supply(self, address: str, chain: str = "ethereum") -> str:
        return await self._call(
            chain, module="stats", action="tokensupply", contractaddress=address
        )

    async def get_token_holders(
        self, address: str, chain: str = "ethereum", page: int = 1, offset: int = 100
    ) -> list[dict]:
        # Pro-tier endpoint; gracefully degrade if the key tier doesn't include it.
        try:
            result = await self._call(
                chain,
                module="token",
                action="tokenholderlist",
                contractaddress=address,
                page=page,
                offset=offset,
            )
            return result if isinstance(result, list) else []
        except EtherscanError:
            return []

    async def get_recent_txs(
        self, address: str, chain: str = "ethereum", offset: int = 25
    ) -> list[dict]:
        result = await self._call(
            chain,
            module="account",
            action="txlist",
            address=address,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=offset,
            sort="desc",
        )
        return result if isinstance(result, list) else []
