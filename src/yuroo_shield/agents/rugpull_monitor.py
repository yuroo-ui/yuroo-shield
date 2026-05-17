"""Rugpull Monitor Agent — recent activity heuristics.

Uses the contract's *real* creation timestamp from Etherscan's
``getcontractcreation`` endpoint rather than the timestamp of the most recent N
transactions (which collapses to "minutes old" for any active token).
"""
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
        # Real creation timestamp (canonical)
        created_ts = await self._es.get_contract_creation_timestamp(address, chain)
        txs = await self._es.get_recent_txs(address, chain, offset=50)

        report = RugpullReport(recent_tx_count=len(txs), contract_age_days=None)

        if created_ts:
            age_days = (time.time() - created_ts) / 86400
            report.contract_age_days = round(age_days, 2)
            if age_days < 7:
                report.signals.append(
                    RugpullSignal(
                        name="very_new_contract",
                        severity="high",
                        detail=f"Contract is only {age_days:.1f} days old.",
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

        if not txs:
            report.signals.append(
                RugpullSignal(
                    name="no_recent_activity",
                    severity="medium",
                    detail="No recent transactions returned by explorer.",
                )
            )
            return report

        # Honeypot indicator: many recent reverts
        failed = sum(1 for t in txs if str(t.get("isError", "0")) == "1")
        if failed and failed / len(txs) > 0.3:
            report.signals.append(
                RugpullSignal(
                    name="high_failure_rate",
                    severity="high",
                    detail=(
                        f"{failed}/{len(txs)} recent transactions reverted "
                        "(honeypot indicator)."
                    ),
                )
            )

        return report
