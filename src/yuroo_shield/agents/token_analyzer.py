"""Token Analyzer Agent — supply, holders, distribution."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Settings
from ..etherscan import EtherscanClient


@dataclass
class TokenSignal:
    name: str
    severity: str
    detail: str


@dataclass
class TokenReport:
    total_supply: int | None
    holder_sample_size: int
    top10_concentration: float | None  # 0..1
    signals: list[TokenSignal] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_supply": self.total_supply,
            "holder_sample_size": self.holder_sample_size,
            "top10_concentration": self.top10_concentration,
            "signals": [s.__dict__ for s in self.signals],
        }


class TokenAnalyzerAgent:
    name = "token_analyzer"

    def __init__(self, etherscan: EtherscanClient, settings: Settings):
        self._es = etherscan
        self._settings = settings

    async def scan(self, address: str, chain: str) -> TokenReport:
        supply_raw = await self._es.get_token_supply(address, chain)
        try:
            total_supply = int(supply_raw)
        except (TypeError, ValueError):
            total_supply = None

        holders = await self._es.get_token_holders(address, chain, offset=100)
        report = TokenReport(
            total_supply=total_supply,
            holder_sample_size=len(holders),
            top10_concentration=None,
        )

        if not holders:
            report.signals.append(
                TokenSignal(
                    name="holder_data_unavailable",
                    severity="info",
                    detail="Holder list endpoint requires Etherscan Pro tier.",
                )
            )
            return report

        balances = []
        for h in holders[:10]:
            try:
                balances.append(int(h.get("TokenHolderQuantity", 0)))
            except (TypeError, ValueError):
                continue

        if total_supply and balances:
            top10 = sum(balances) / total_supply if total_supply > 0 else 0
            report.top10_concentration = round(top10, 4)
            if top10 > self._settings.holder_concentration_threshold:
                report.signals.append(
                    TokenSignal(
                        name="high_concentration",
                        severity="high",
                        detail=(
                            f"Top 10 holders own {top10 * 100:.1f}% of supply "
                            f"(threshold {self._settings.holder_concentration_threshold * 100:.0f}%)."
                        ),
                    )
                )

        return report
