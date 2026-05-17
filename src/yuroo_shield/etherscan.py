"""Etherscan v2 multichain client.

Docs: https://docs.etherscan.io/etherscan-v2
Single endpoint https://api.etherscan.io/v2/api with chainid query param.

Includes retry/backoff for rate-limit (NOTOK) responses on the free tier
(5 requests/second).
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from .config import CHAIN_IDS

ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"
_RATE_LIMIT_TOKENS = ("NOTOK", "Max rate limit reached", "rate limit")


class EtherscanError(RuntimeError):
    pass


class EtherscanClient:
    def __init__(self, api_key: str, timeout: float = 20.0, max_retries: int = 4):
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY is required")
        self._api_key = api_key
        self._max_retries = max_retries
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
        last_err: str | None = None
        for attempt in range(self._max_retries):
            r = await self._client.get(ETHERSCAN_V2_BASE, params=params)
            r.raise_for_status()
            data = r.json()
            if "status" in data and data["status"] == "0":
                msg = data.get("message", "")
                result = data.get("result", "")
                # Empty-result conditions are legit
                if msg and "No " in msg:
                    return []
                # Rate limit → backoff and retry
                combined = f"{msg} {result}".lower()
                if any(t.lower() in combined for t in _RATE_LIMIT_TOKENS):
                    last_err = f"{msg} {result}"
                    await asyncio.sleep(0.4 * (2 ** attempt))
                    continue
                raise EtherscanError(f"{params.get('action')}: {msg or result}")
            return data.get("result", data)
        raise EtherscanError(
            f"{params.get('action')}: rate-limited after {self._max_retries} retries "
            f"({last_err})"
        )

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

    async def get_contract_creation(
        self, address: str, chain: str = "ethereum"
    ) -> dict:
        """Returns the creation tx hash + creator address + timestamp, or {} on miss.

        Etherscan v2 endpoint: contract.getcontractcreation
        Result fields include: contractCreator, txHash, blockNumber, timestamp.
        """
        try:
            result = await self._call(
                chain,
                module="contract",
                action="getcontractcreation",
                contractaddresses=address,
            )
        except EtherscanError:
            return {}
        if isinstance(result, list) and result:
            return result[0]
        return {}

    async def get_block_timestamp(
        self, block_number: int | str, chain: str = "ethereum"
    ) -> int | None:
        """Resolve a block number to its UNIX timestamp via the proxy module."""
        try:
            block_hex = hex(int(block_number))
        except (TypeError, ValueError):
            return None
        try:
            result = await self._call(
                chain,
                module="proxy",
                action="eth_getBlockByNumber",
                tag=block_hex,
                boolean="false",
            )
        except EtherscanError:
            return None
        if isinstance(result, dict) and result.get("timestamp"):
            try:
                return int(result["timestamp"], 16)
            except (TypeError, ValueError):
                return None
        return None

    async def get_contract_creation_timestamp(
        self, address: str, chain: str = "ethereum"
    ) -> int | None:
        """Resolve contract creation to a UNIX timestamp.

        Etherscan v2 includes ``timestamp`` directly in getcontractcreation.
        Falls back to eth_getBlockByNumber if that field is missing on a chain.
        """
        info = await self.get_contract_creation(address, chain)
        if not info:
            return None
        ts_raw = info.get("timestamp")
        if ts_raw:
            try:
                return int(ts_raw)
            except (TypeError, ValueError):
                pass
        block_no = info.get("blockNumber")
        if block_no:
            return await self.get_block_timestamp(block_no, chain)
        return None
