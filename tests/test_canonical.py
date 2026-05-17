"""Tests for canonical token allowlist."""
from yuroo_shield.canonical import lookup


def test_dai_recognized_lowercase():
    assert lookup("ethereum", "0x6b175474e89094c44da98b954eedeac495271d0f") == "DAI"


def test_dai_recognized_checksum():
    assert lookup("ethereum", "0x6B175474E89094C44Da98b954EedeAC495271d0F") == "DAI"


def test_chain_case_insensitive():
    assert lookup("Ethereum", "0x6B175474E89094C44Da98b954EedeAC495271d0F") == "DAI"


def test_unknown_returns_none():
    assert lookup("ethereum", "0x0000000000000000000000000000000000000001") is None


def test_wrong_chain_returns_none():
    # DAI on Ethereum, asked on BSC → not canonical
    assert lookup("bsc", "0x6b175474e89094c44da98b954eedeac495271d0f") is None
