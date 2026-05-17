"""Rugpull Monitor Agent — recent activity heuristics."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..etherscan import EtherscanClient


@dataclass
class RugpullSignal:
    name: str
    severity: str
    detail: str


@dataclass
class RugpullReport:
    recent_tx_count: int
    contract_age_days: float | None
    signals: list[RugpullSignal] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "recent_tx_count": self.recent_tx_count,
            "contract_age_days": self.contract_age_days,
            "signals": [s.__dict__ for s in self.signals],
        }


class RugpullMonitorAgent:
    name = "rugpull_monitor"

    def __init__(self, etherscan: EtherscanClient):
        self._es = etherscan

    async def scan(self, address: str, chain: str) -> RugpullReport:
        txs = await self._es.get_recent_txs(address, chain, offset=50)
        report = RugpullReport(recent_tx_count=len(txs), contract_age_days=None)

        if not txs:
            report.signals.append(
                RugpullSignal(
                    name="no_recent_activity",
                    severity="medium",
                    detail="No recent transactions returned by explorer.",
                )
            )
            return report

        # Oldest tx in returned window is sorted desc, so use last
        try:
            oldest_ts = int(txs[-1].get("timeStamp", 0))
            if oldest_ts:
                age_days = (time.time() - oldest_ts) / 86400
                report.contract_age_days = round(age_days, 2)
                if age_days < 7:
                    report.signals.append(
                        RugpullSignal(
                            name="very_new_contract",
                            severity="high",
                            detail=f"Contract observed for {age_days:.1f} days only.",
                        )
                    )
                elif age_days < 30:
                    report.signals.append(
                        RugpullSignal(
                            name="new_contract",
                            severity="medium",
                            detail=f"Contract is {age_days:.0f} days old.",
                        )
                    )
        except (ValueError, TypeError):
            pass

        # Many failed txs = honeypot indicator
        failed = sum(1 for t in txs if str(t.get("isError", "0")) == "1")
        if failed and failed / len(txs) > 0.3:
            report.signals.append(
                RugpullSignal(
                    name="high_failure_rate",
                    severity="high",
                    detail=f"{failed}/{len(txs)} recent transactions reverted (honeypot indicator).",
                )
            )

        return report
