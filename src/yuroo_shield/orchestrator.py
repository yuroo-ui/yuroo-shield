"""Top-level orchestrator: coordinate all 5 agents, return one ContractReport."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum

from .agents import (
    ContractScannerAgent,
    GoPlusIntelAgent,
    ReportGeneratorAgent,
    RugpullMonitorAgent,
    ThreatIntelAgent,
    TokenAnalyzerAgent,
)
from .agents.report_generator import VerdictInputs
from .canonical import lookup as canonical_lookup
from .config import Settings, load_settings
from .etherscan import EtherscanClient
from .llm import LLMClient


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ContractReport:
    address: str
    chain: str
    risk_score: int
    risk_level: RiskLevel
    recommendation: str
    summary: str
    canonical_name: str | None = None
    agent_outputs: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "chain": self.chain,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "recommendation": self.recommendation,
            "summary": self.summary,
            "canonical_name": self.canonical_name,
            "agent_outputs": self.agent_outputs,
        }


class AgentOrchestrator:
    """Orchestrate all agents. Independent on-chain calls run in parallel."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self._etherscan = EtherscanClient(self.settings.etherscan_api_key)
        self._llm = LLMClient(
            api_key=self.settings.llm_api_key,
            base_url=self.settings.llm_base_url,
            model=self.settings.llm_model,
        )
        self._scanner = ContractScannerAgent(self._etherscan, self._llm)
        self._rugpull = RugpullMonitorAgent(self._etherscan)
        self._token = TokenAnalyzerAgent(self._etherscan, self.settings)
        self._threat = ThreatIntelAgent()
        self._goplus = GoPlusIntelAgent()
        self._report = ReportGeneratorAgent(self._llm)

    async def aclose(self) -> None:
        await self._etherscan.aclose()
        await self._llm.aclose()
        await self._goplus.aclose()

    async def __aenter__(self) -> "AgentOrchestrator":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def scan_contract(self, address: str, chain: str = "ethereum") -> ContractReport:
        scanner_t = asyncio.create_task(self._scanner.scan(address, chain))
        rugpull_t = asyncio.create_task(self._rugpull.scan(address, chain))
        token_t = asyncio.create_task(self._token.scan(address, chain))
        threat_t = asyncio.create_task(self._threat.scan(address, chain))
        goplus_t = asyncio.create_task(self._goplus.scan(address, chain))

        scanner = await scanner_t
        rugpull = await rugpull_t
        token = await token_t
        threat = await threat_t
        goplus = await goplus_t

        verdict = await self._report.generate(
            VerdictInputs(
                scanner=scanner.to_dict(),
                rugpull=rugpull.to_dict(),
                token=token.to_dict(),
                threat=threat.to_dict(),
                goplus=goplus.to_dict(),
            )
        )

        # Canonical token dampening: blue-chip allowlist caps the verdict at LOW.
        canonical_name = canonical_lookup(chain, address)
        risk_score = verdict.risk_score
        risk_level = RiskLevel(verdict.risk_level)
        recommendation = verdict.recommendation
        summary = verdict.summary
        if canonical_name:
            risk_score = min(risk_score, 5)
            risk_level = RiskLevel.LOW if risk_score >= 5 else RiskLevel.SAFE
            recommendation = (
                f"Canonical {canonical_name} contract on {chain}. "
                "Heuristic findings on widely-audited contracts are typically "
                "false positives; verify on-chain before treating as malicious."
            )
            # Always replace the LLM summary for canonical tokens — its score
            # context was the pre-dampening number, which would mislead the user.
            summary = (
                f"This is the canonical {canonical_name} contract on {chain}. "
                "Risk dampened to LOW; any heuristic findings are advisory."
            )

        return ContractReport(
            address=address,
            chain=chain,
            risk_score=risk_score,
            risk_level=risk_level,
            recommendation=recommendation,
            summary=summary,
            canonical_name=canonical_name,
            agent_outputs={
                "scanner": scanner.to_dict(),
                "rugpull": rugpull.to_dict(),
                "token": token.to_dict(),
                "threat": threat.to_dict(),
                "goplus": goplus.to_dict(),
            },
        )
