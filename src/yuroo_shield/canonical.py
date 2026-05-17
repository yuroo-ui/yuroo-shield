"""Canonical token allowlist — well-known tokens whose findings are advisory only.

These contracts are widely-audited blue chips. Any heuristic finding against them
is overwhelmingly likely to be a false positive (e.g. governance-controlled mint,
upgradeability via timelocked proxy, etc.).

We don't *suppress* findings — that would hide real changes if a contract gets
compromised. We tag the report with ``canonical`` metadata so the orchestrator
can dampen the score and so the verdict copy reflects the contract's standing.
"""
from __future__ import annotations

# (chain, lowercase address) → friendly name
CANONICAL: dict[tuple[str, str], str] = {
    ("ethereum", "0x6b175474e89094c44da98b954eedeac495271d0f"): "DAI",
    ("ethereum", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): "USDC",
    ("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7"): "USDT",
    ("ethereum", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"): "WETH",
    ("ethereum", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"): "WBTC",
    ("ethereum", "0x514910771af9ca656af840dff83e8264ecf986ca"): "LINK",
    ("ethereum", "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"): "UNI",
    ("polygon", "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"): "DAI",
    ("polygon", "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"): "USDC",
    ("polygon", "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"): "USDT",
    ("bsc", "0x55d398326f99059ff775485246999027b3197955"): "USDT",
    ("bsc", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"): "USDC",
    ("arbitrum", "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"): "USDC.e",
    ("arbitrum", "0xaf88d065e77c8cc2239327c5edb3a432268e5831"): "USDC",
    ("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"): "USDC",
    ("optimism", "0x0b2c639c533813f4aa9d7837caf62653d097ff85"): "USDC",
}


def lookup(chain: str, address: str) -> str | None:
    """Return the friendly name if (chain, address) is a canonical token, else None."""
    return CANONICAL.get((chain.lower(), address.lower()))
