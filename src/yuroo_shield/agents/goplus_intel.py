"""GoPlus Intel Agent — public token-security feed (no API key required).

Docs: https://docs.gopluslabs.io/reference/api-overview-token-security
Endpoint: https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses=0x...

Returns string flags ("0"/"1") for risk attributes. We map them to severity-weighted findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from ..config import CHAIN_IDS

GOPLUS_BASE = "https://api.gopluslabs.io/api/v1/token_security"

# Severity per flag when value == "1"
_RISK_FLAGS: dict[str, tuple[str, str]] = {
    "is_honeypot": ("critical", "Token classified as a honeypot."),
    "hidden_owner": ("critical", "Hidden owner detected."),
    "selfdestruct": ("critical", "Contract can self-destruct."),
    "can_take_back_ownership": ("high", "Owner can be reclaimed after renouncement."),
    "owner_change_balance": ("high", "Owner can change arbitrary balances."),
    "is_blacklisted": ("high", "Address is blacklisted by the contract."),
    "is_mintable": ("medium", "Token supply is mintable by the owner."),
    "external_call": ("medium", "Contract makes external calls in transfer."),
    "trading_cooldown": ("low", "Trading cooldown logic present."),
    "is_anti_whale": ("info", "Anti-whale limits enforced."),
}


@dataclass
class GoPlusSignal:
    name: str
    severity: str
    detail: str


@dataclass
class GoPlusReport:
    available: bool
    raw: dict = field(default_factory=dict)
    signals: list[GoPlusSignal] = field(default_factory=list)
    buy_tax: float | None = None
    sell_tax: float | None = None
    holder_count: int | None = None
    is_open_source: bool | None = None

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "buy_tax": self.buy_tax,
            "sell_tax": self.sell_tax,
            "holder_count": self.holder_count,
            "is_open_source": self.is_open_source,
            "signals": [s.__dict__ for s in self.signals],
        }


class GoPlusIntelAgent:
    name = "goplus_intel"

    def __init__(self, http: httpx.AsyncClient | None = None, timeout: float = 15.0):
        self._owns_client = http is None
        self._http = http or httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    @staticmethod
    def _chain_id(chain: str) -> int | None:
        return CHAIN_IDS.get(chain.lower())

    @staticmethod
    def _to_float(s: str | None) -> float | None:
        try:
            return float(s) if s not in (None, "", "0") or s == "0" else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _flag(s: str | None) -> bool:
        return str(s) == "1"

    async def scan(self, address: str, chain: str) -> GoPlusReport:
        chain_id = self._chain_id(chain)
        if chain_id is None:
            return GoPlusReport(available=False)

        try:
            r = await self._http.get(
                f"{GOPLUS_BASE}/{chain_id}",
                params={"contract_addresses": address},
            )
            r.raise_for_status()
            payload = r.json()
        except (httpx.HTTPError, ValueError):
            return GoPlusReport(available=False)

        # GoPlus keys the result dict by lowercase address
        result_map = payload.get("result") or {}
        if not isinstance(result_map, dict) or not result_map:
            return GoPlusReport(available=False)
        data = next(iter(result_map.values()), {}) or {}

        report = GoPlusReport(available=True, raw=data)
        report.is_open_source = self._flag(data.get("is_open_source"))
        try:
            report.holder_count = int(data.get("holder_count") or 0) or None
        except (TypeError, ValueError):
            report.holder_count = None

        # Taxes are returned as strings like "0", "0.05" (= 5%)
        for field_name in ("buy_tax", "sell_tax"):
            try:
                v = data.get(field_name)
                if v in (None, ""):
                    continue
                pct = float(v)
                setattr(report, field_name, pct)
                if pct >= 0.10:
                    report.signals.append(
                        GoPlusSignal(
                            name=f"high_{field_name}",
                            severity="high",
                            detail=f"{field_name.replace('_', ' ').title()} = {pct * 100:.1f}%.",
                        )
                    )
                elif pct >= 0.05:
                    report.signals.append(
                        GoPlusSignal(
                            name=f"elevated_{field_name}",
                            severity="medium",
                            detail=f"{field_name.replace('_', ' ').title()} = {pct * 100:.1f}%.",
                        )
                    )
            except (TypeError, ValueError):
                continue

        # is_open_source == "0" is a high signal on its own
        if report.is_open_source is False:
            report.signals.append(
                GoPlusSignal(
                    name="not_open_source",
                    severity="high",
                    detail="GoPlus reports the contract is not open-source.",
                )
            )

        for flag, (severity, detail) in _RISK_FLAGS.items():
            if self._flag(data.get(flag)):
                report.signals.append(GoPlusSignal(name=flag, severity=severity, detail=detail))

        return report
