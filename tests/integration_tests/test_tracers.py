
import pytest
from web3 import Web3
from web3._utils.transactions import fill_transaction_defaults

from .expected_constants import (
    EXPECTED_CALLTRACERS,
    EXPECTED_CONTRACT_CREATE_TRACER,
    EXPECTED_STRUCT_TRACER,
    EXPECTED_ETH_TX_FAILED_AT_ANTE_TRACER,
)
from .network import setup_ethermint
from .utils import (
    ADDRS,
    CONTRACTS,
    KEYS,
    deploy_contract,
    derive_new_account,
    derive_new_address,
    send_raw_transaction_mempool,
    send_transaction,
    w3_wait_for_new_blocks,
)


@pytest.fixture(scope="module")
def custom_ethermint_long_timeout(tmp_path_factory):
    path = tmp_path_factory.mktemp("debug")
    yield from setup_ethermint(path, 26850, long_timeout_commit=True)


@pytest.fixture(scope="module")
def custom_ethermint_small_max_gas(tmp_path_factory):
    path = tmp_path_factory.mktemp("debug")
    yield from setup_ethermint_config(path, 26900, "long_timeout_commit_small_max_gas.jsonnet")


def test_tracers(ethermint_rpc_ws):
    w3: Web3 = ethermint_rpc_ws.w3
    eth_rpc = w3.provider
    gas_price = w3.eth.gas_price
    tx = {"to": ADDRS["community"], "value": 100, "gasPrice": gas_price}
    tx_hash = send_transaction(w3, tx, KEYS["validator"])["transactionHash"].hex()

    tx_res = eth_rpc.make_request("debug_traceTransaction", [tx_hash])
    assert tx_res["result"] == EXPECTED_STRUCT_TRACER, ""

    tx_res = eth_rpc.make_request(
        "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}]
    )
    assert tx_res["result"] == EXPECTED_CALLTRACERS, ""

    tx_res = eth_rpc.make_request(
        "debug_traceTransaction",
        [tx_hash, {"tracer": "callTracer", "tracerConfig": "{'onlyTopCall':True}"}],
    )
    assert tx_res["result"] == EXPECTED_CALLTRACERS, ""

    _, tx = deploy_contract(
        w3,
        CONTRACTS["TestERC20A"],
    )
    tx_hash = tx["transactionHash"].hex()

    w3_wait_for_new_blocks(w3, 1)

    tx_res = eth_rpc.make_request(
        "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}]
    )
    tx_res["result"]["to"] = EXPECTED_CONTRACT_CREATE_TRACER["to"]
    assert tx_res["result"] == EXPECTED_CONTRACT_CREATE_TRACER, ""


def test_debug_traceblock_eth_tx_failed_at_ante(custom_ethermint_long_timeout):
    w3: Web3 = custom_ethermint_long_timeout.w3
    eth_rpc = w3.provider

    sender_account = derive_new_account()
    sender = sender_account.address
    block_number = hex(w3.eth.block_number)

    fund_sender_tx = { "to": sender, "value": 100000000000000000000, "gasPrice": w3.eth.gas_price }
    send_transaction(w3, fund_sender_tx, KEYS["community"])

    receiver = derive_new_address(2)
    sender_nonce = w3.eth.get_transaction_count(sender, block_number)

    tx = fill_transaction_defaults(w3, {
        "from": sender,
        "to": receiver,
        "value": 40000000000000000000,
        "gasPrice": w3.eth.gas_price,
        "nonce": sender_nonce,
    })
    tx2 = fill_transaction_defaults(w3, {
        "from": sender,
        "to": receiver,
        "value": 40000000000000000000,
        "gasPrice": w3.eth.gas_price,
        "nonce": sender_nonce + 1,
    })
    insufficient_fund_tx = fill_transaction_defaults(w3, {
        "from": sender,
        "to": receiver,
        "value": 40000000000000000000,
        "gasPrice": w3.eth.gas_price,
        "nonce": sender_nonce + 2,
    })
    txhash = send_raw_transaction_mempool(w3, tx, sender_account.key)
    send_raw_transaction_mempool(w3, tx2, sender_account.key)
    # this transaction fails during execution because of insufficient balance at ante handler
    send_raw_transaction_mempool(w3, insufficient_fund_tx, sender_account.key)
    receipt = w3.eth.wait_for_transaction_receipt(txhash, timeout=20)

    expected_result = EXPECTED_ETH_TX_FAILED_AT_ANTE_TRACER.copy()
    expected_result[0]["result"]["from"] = sender.lower()
    expected_result[0]["result"]["to"] = receiver.lower()
    expected_result[1]["result"]["from"] = sender.lower()
    expected_result[1]["result"]["to"] = receiver.lower()

    block_trace_res = eth_rpc.make_request("debug_traceBlockByHash", [receipt.blockHash.hex(), { "tracer": "callTracer" }])
    assert block_trace_res["result"] == expected_result

    block_trace_res = eth_rpc.make_request("debug_traceBlockByNumber", [hex(receipt.blockNumber), { "tracer": "callTracer" }])
    assert block_trace_res["result"] == expected_result

