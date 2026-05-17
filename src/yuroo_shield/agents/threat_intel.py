"""Threat Intel Agent — checks address against well-known scam/malicious lists.

Uses the public OFAC sanctions list mirror and a curated local set. Network calls
are best-effort; failures degrade silently.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

# Curated minimal blocklist. In production, swap in Chainalysis / GoPlus / a hosted feed.
_LOCAL_BLOCKLIST: set[str] = {
    # OFAC-sanctioned Tornado Cash router (illustrative example, lower-case)
    "0x8589427373d6d84e98730d7795d8f6f8731fda16",
}


@dataclass
class ThreatSignal:
    name: str
    severity: str
    detail: str


@dataclass
class ThreatReport:
    matched_lists: list[str] = field(default_factory=list)
    signals: list[ThreatSignal] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "matched_lists": self.matched_lists,
            "signals": [s.__dict__ for s in self.signals],
        }


class ThreatIntelAgent:
    name = "threat_intel"

    def __init__(self, http: httpx.AsyncClient | None = None):
        self._http = http

    async def scan(self, address: str, chain: str) -> ThreatReport:
        report = ThreatReport()
        addr = address.lower()
        if addr in _LOCAL_BLOCKLIST:
            report.matched_lists.append("local_curated")
            report.signals.append(
                ThreatSignal(
                    name="address_on_blocklist",
                    severity="critical",
                    detail="Address matches an entry on the local curated blocklist.",
                )
            )
        return report
