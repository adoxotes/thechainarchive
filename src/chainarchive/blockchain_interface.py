from pykeepass import PyKeePass
from pykeepass.entry import Entry as KeePassEntry
from getpass import getpass
from web3 import Web3
from web3.types import TxParams
from typing import Callable, Union, cast
from web3.middleware import ExtraDataToPOAMiddleware
from dataclasses import dataclass
from chainarchive.encryption import (
    compute_hash,
    split_chunks,
    encrypt,
    decrypt,
    prepare,
)
from functools import lru_cache


@dataclass
class Entry:
    id: str
    # Either store list of values or dump json
    slots: Union[list[int], str]


@dataclass
class TransactionLog:
    blockNumber: int
    transactionHash: str
    entry: Entry


@dataclass
class AnchorContract:
    address: str
    rpc: str
    abi: str
    genesis: int = 0


polygon_amoy_testnet_contract = AnchorContract(
    address="0x97F29840cd1CFCa8b13c93560F011ce87bCBF8D7",
    rpc="https://rpc-amoy.polygon.technology",
    abi='[{"inputs":[{"internalType":"uint256","name":"provided","type":"uint256"},{"internalType":"uint256","name":"maximum","type":"uint256"}],"name":"ArrayTooLong","type":"error"},{"inputs":[],"name":"EmptySlotsNotAllowed","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"id","type":"bytes32"},{"indexed":false,"internalType":"bytes32[]","name":"slots","type":"bytes32[]"}],"name":"Entry","type":"event"},{"inputs":[],"name":"MAX_SLOTS","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"id","type":"bytes32"},{"internalType":"bytes32[]","name":"slots","type":"bytes32[]"}],"name":"anchorData","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    genesis=31502336,
)


@dataclass
class Wallet:
    address: str
    private_key: str

    def __init__(self, keypass_file: str, wallet_name: str):
        kp = PyKeePass(keypass_file, password=getpass("KeePass Password: "))

        # Optimistically assume that we find the wallet
        wallet = cast(KeePassEntry, kp.find_entries(title=wallet_name, first=True))

        if wallet == None:
            raise LookupError(f"Cannot find {wallet_name} in KeePass")

        # Not sure why pylance is not finding these
        self.address = cast(str, wallet.username)
        self.private_key = cast(str, wallet.password)


class ChainArchive:
    def __init__(self, contract: AnchorContract = polygon_amoy_testnet_contract):
        self.contract = contract

        # Save contract address separately for interfacing with w3.eth.contract
        self._checksum_contract_address = Web3.to_checksum_address(contract.address)
        self.w3 = Web3(Web3.HTTPProvider(contract.rpc))

    @property
    @lru_cache
    def feestructure(self) -> dict[str, int]:
        # Check if we are on a chain that needs PoA middleware
        if self.w3.eth.chain_id in [137, 80002]:
            self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        # Fetch current fee data (EIP-1559)
        latest_block = self.w3.eth.get_block("latest")
        base_fee = latest_block.get("baseFeePerGas", self.w3.to_wei(30, "gwei"))

        # validator tip
        max_priority_fee = self.w3.eth.max_priority_fee

        # safe max fee buffer
        max_fee = (base_fee * 2) + max_priority_fee

        return {
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority_fee,
        }

    def store(self, entry: Entry, wallet: Wallet, encryption_key: str) -> str:
        ctr = self.w3.eth.contract(
            address=self._checksum_contract_address, abi=self.contract.abi
        )

        account_checksum_address = self.w3.to_checksum_address(wallet.address)

        # Prepare transaction function
        tx_func = ctr.functions.anchorData(
            # Data can be retrieved with this hash
            compute_hash(entry.id, encryption_key),
            # The contract assumes bytes32 array
            split_chunks(encrypt(prepare(entry.slots), encryption_key), chunk_size=32),
        )

        # For typechecking say you're sure of data structure here
        tx_params = cast(
            TxParams,
            {
                "chainId": self.w3.eth.chain_id,
                "nonce": self.w3.eth.get_transaction_count(
                    account_checksum_address, "pending"
                ),
                **self.feestructure,
            },
        )

        # dynamically estimate gas
        try:
            tx_params["gas"] = tx_func.estimate_gas({"from": account_checksum_address})
        except Exception as e:
            # TODO: log warning
            # Fallback if estimation fails
            tx_params["gas"] = 200000

        # Build transaction
        tx = tx_func.build_transaction(tx_params)

        # Sign and broadcast
        signed_tx = self.w3.eth.account.sign_transaction(
            tx, private_key=wallet.private_key
        )
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        # Return transaction hash for logging purposes
        return tx_hash.hex()

    def retrieve(self, id: str, key: str, unpack: Callable) -> list[TransactionLog]:
        target_id = compute_hash(id, key)

        # Create the contract instance
        ctr = self.w3.eth.contract(
            address=self._checksum_contract_address, abi=self.contract.abi
        )

        # fetch logs
        logs = ctr.events.Entry().get_logs(
            from_block=self.contract.genesis,
            to_block="latest",
            argument_filters={"id": target_id},
        )

        # No entries found
        if not logs:
            return []

        return [
            TransactionLog(
                blockNumber=log["blockNumber"],
                transactionHash=log["transactionHash"].hex(),
                entry=Entry(
                    id=id,
                    slots=unpack(
                        decrypt(b"".join(log["args"]["slots"]), bytes.fromhex(key))
                    ),
                ),
            )
            for log in logs
        ]
