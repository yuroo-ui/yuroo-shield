"""Contract Scanner Agent — multi-pass static + LLM-assisted vulnerability detection.

Heuristic checks (no LLM required):
- Source verification status
- Ownership renouncement detection (well-known patterns)
- Proxy / upgradeable contract detection
- Suspicious function names (mint, blacklist, setTax, pause)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..etherscan import EtherscanClient
from ..llm import LLMClient

# Ownership renounce sentinels in `owner()` view return / source code
_RENOUNCE_PATTERNS = (
    "0x000000000000000000000000000000000000dead",
    "0x0000000000000000000000000000000000000000",
)

_SUSPICIOUS_FN_PATTERNS = {
    "hidden_mint": re.compile(r"function\s+\w*[mM]int\w*\s*\(", re.MULTILINE),
    "blacklist": re.compile(r"function\s+\w*[bB]lacklist\w*\s*\(", re.MULTILINE),
    "set_tax": re.compile(r"function\s+set\w*[tT]ax\w*\s*\(", re.MULTILINE),
    "pause": re.compile(r"function\s+_?pause\s*\(", re.MULTILINE),
    "set_max_tx": re.compile(r"function\s+set\w*[mM]ax(Tx|Wallet)\w*\s*\(", re.MULTILINE),
    "exclude_fee": re.compile(r"function\s+excludeFrom\w*\s*\(", re.MULTILINE),
}


@dataclass
class ScannerFinding:
    name: str
    severity: str  # info, low, medium, high, critical
    detail: str


@dataclass
class ScannerReport:
    verified: bool
    proxy: bool
    contract_name: str
    compiler_version: str
    findings: list[ScannerFinding] = field(default_factory=list)
    llm_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "verified": self.verified,
            "proxy": self.proxy,
            "contract_name": self.contract_name,
            "compiler_version": self.compiler_version,
            "findings": [f.__dict__ for f in self.findings],
            "llm_summary": self.llm_summary,
        }


class ContractScannerAgent:
    name = "contract_scanner"

    def __init__(self, etherscan: EtherscanClient, llm: LLMClient):
        self._es = etherscan
        self._llm = llm

    async def scan(self, address: str, chain: str) -> ScannerReport:
        src = await self._es.get_source_code(address, chain)
        verified = bool(src.get("SourceCode"))
        report = ScannerReport(
            verified=verified,
            proxy=str(src.get("Proxy", "0")) == "1",
            contract_name=src.get("ContractName", "") or "",
            compiler_version=src.get("CompilerVersion", "") or "",
        )

        if not verified:
            report.findings.append(
                ScannerFinding(
                    name="unverified_source",
                    severity="high",
                    detail="Contract source code is not verified on the explorer.",
                )
            )
            return report

        source = src.get("SourceCode", "") or ""
        # Etherscan sometimes wraps multi-file source in `{{...}}`
        source_text = source.lstrip("{").rstrip("}")

        for finding_name, pattern in _SUSPICIOUS_FN_PATTERNS.items():
            if pattern.search(source_text):
                severity = "medium" if finding_name in {"pause", "set_max_tx"} else "high"
                report.findings.append(
                    ScannerFinding(
                        name=finding_name,
                        severity=severity,
                        detail=f"Source contains pattern '{finding_name}'.",
                    )
                )

        if not any(p in source_text.lower() for p in _RENOUNCE_PATTERNS):
            report.findings.append(
                ScannerFinding(
                    name="ownership_not_renounced",
                    severity="low",
                    detail="No renounce sentinel address found in source.",
                )
            )

        if self._llm.enabled and source_text:
            # Trim to keep token use bounded
            snippet = source_text[:8000]
            report.llm_summary = await self._llm.reason(
                prompt=(
                    "Review this Solidity source for security issues. "
                    "List up to 5 concrete risks with severity. Be concise.\n\n"
                    f"```solidity\n{snippet}\n```"
                ),
                system="You are a smart contract security auditor.",
            )

        return report
