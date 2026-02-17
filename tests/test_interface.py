import pytest
from getpass import getpass
from pathlib import Path
from chainarchive import Wallet, Entry, ChainArchive, unpack_list


@pytest.fixture
def chainarch():
    return ChainArchive()


@pytest.fixture
def keepass_file():
    """Returns the absolute path to the test data directory."""
    return Path(__file__).parent / "test.kdbx"


def test_wallet_loading(monkeypatch, keepass_file):
    # Simulate the user typing a super secret password
    monkeypatch.setattr("getpass.getpass", lambda _: "passw0rd")
    Wallet(keypass_file=keepass_file, wallet_name="Account 1")

    # Also test for invalid entry
    with pytest.raises(LookupError):
        monkeypatch.setattr("getpass.getpass", lambda _: "passw0rd")
        Wallet(keypass_file=keepass_file, wallet_name="Account >9000")


def test_retrieve(chainarch: ChainArchive):
    demo_decryption_key = (
        "d1a3f6409ca44c81d8742c6de4d72e866d78e8790ff29177796aba050a7c319f"
    )
    entries = chainarch.retrieve("id-demo", demo_decryption_key, unpack_list)
    assert entries[0].entry == Entry("id-demo", [1, 2, 3, 4, 5])
    assert (
        entries[0].transactionHash
        == "13e3befaca922ca5ebf4bcfa8f2f0ca690f21907a7452d61a73a0826fa001011"
    )
