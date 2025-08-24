#!/usr/bin/env python3
from typing import List, Tuple

from bip32 import BIP32
from connectrum.client import StratumClient
from tqdm import tqdm

import scripts
from descriptors import Path, Script, ScriptIterator
from scripts import ScriptType

MAX_BATCH_SIZE = 100

# Nothing a server says about an output is taken on faith: these are the shapes a real one has
TXID_LENGTH_IN_BYTES = 32
MAX_OUTPUT_INDEX = 0xffff_ffff
MAX_MONEY_IN_SAT = 21_000_000 * 100_000_000


class Utxo:
    """
    Data needed to spend a currently unspent transaction output.
    """

    def __init__(self, txid: str, output_index: int, amount_in_sat: int, path: Path, script_type: ScriptType):
        self.txid = txid
        self.output_index = output_index
        self.amount_in_sat = amount_in_sat
        self.path = path
        self.script_type = script_type


async def scan_master_key(
        client: StratumClient,
        master_key: BIP32,
        address_gap: int,
        account_gap: int,
        should_batch: bool
) -> List[Utxo]:
    """
    Iterate through all the possible addresses of a master key, in order to find its UTXOs.
    """
    batch_size = MAX_BATCH_SIZE if should_batch else 1
    script_iter = ScriptIterator(master_key, address_gap, account_gap)
    descriptors = set()
    outpoints = set()
    balance = 0
    utxos = []

    # TODO: parallelize fetching

    with tqdm(total=script_iter.total_scripts(), desc='🏃‍♀️  Searching possible addresses') as progress_bar:
        while True:

            # Compute the next batch of scripts
            scripts = []
            for index in range(batch_size):
                script = script_iter.next_script()
                if not script:
                    break
                scripts.append(script)

            if len(scripts) == 0:
                # We are done!
                break

            # Build the next batched request
            batch_request = []
            for script in scripts:
                hash = _electrum_script_hash(script.program)
                batch_request.append(('blockchain.scripthash.get_history', hash))

            responses = await _electrum_rpc(client, batch_request)

            # Using the responses, compute the next batch of *used* scripts
            used_scripts = []
            for script, response in zip(scripts, responses):
                if not isinstance(response, list):
                    raise ValueError(f'The server answered with {response!r} where a history belongs')

                if len(response) == 0:
                    continue

                path, type = script.path_with_account().path, script.type().name

                if (path, type) not in descriptors:
                    descriptors.add((path, type))
                    message = f'🕵   Found used addresses at path={path} address_type={type}'
                    progress_bar.write(message)

                script.set_as_used()
                used_scripts.append(script)

            # Build the next batched request
            batch_request = []
            for script in used_scripts:
                hash = _electrum_script_hash(script.program)
                batch_request.append(('blockchain.scripthash.listunspent', hash))

            responses = await _electrum_rpc(client, batch_request)

            for script, response in zip(used_scripts, responses):
                if not isinstance(response, list):
                    raise ValueError(f'The server answered with {response!r} where a list of outputs belongs')

                for entry in response:
                    utxo = _utxo_from(entry, script)

                    if (utxo.txid, utxo.output_index) in outpoints:
                        raise ValueError(f'The server offered ({utxo.txid}, {utxo.output_index}) twice')

                    outpoints.add((utxo.txid, utxo.output_index))

                    # An output worth nothing is valid by consensus and adds nothing to a sweep,
                    # so it is passed over rather than allowed to stop the recovery
                    if utxo.amount_in_sat == 0:
                        continue

                    balance += utxo.amount_in_sat

                    if balance > MAX_MONEY_IN_SAT:
                        raise ValueError(f'The server has offered more than {MAX_MONEY_IN_SAT} satoshis in all')

                    utxos.append(utxo)

                    message = (f'💰  Found unspent output at ({utxo.txid}, {utxo.output_index}) '
                               f'with {utxo.amount_in_sat} sats')
                    progress_bar.write(message)

            # Update the progress bar
            progress_bar.total = script_iter.total_scripts()
            progress_bar.update(len(scripts))
            progress_bar.refresh()

    return utxos


def _whole_number(value: object, field: str) -> int:
    """
    Read a field that has to be a whole number, refusing anything that only looks like one.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f'The server gave {value!r} as {field}, which is not a whole number')

    return value


def _utxo_from(entry: object, script: Script) -> Utxo:
    """
    Build an unspent output out of what a server said, or refuse what it said.
    """
    if not isinstance(entry, dict):
        raise ValueError(f'The server answered with {entry!r} where an output belongs')

    for field in ['tx_hash', 'tx_pos', 'value']:
        if field not in entry:
            raise ValueError(f'The server left {field} out of {entry!r}')

    given_txid = entry['tx_hash']

    if not isinstance(given_txid, str):
        raise ValueError(f'The server gave {given_txid!r} as a transaction id')

    try:
        raw_txid = bytes.fromhex(given_txid)
    except ValueError:
        raise ValueError(f'The server gave {given_txid!r} as a transaction id')

    if len(raw_txid) != TXID_LENGTH_IN_BYTES:
        raise ValueError(f'The server gave {given_txid!r} as a transaction id')

    # Written back out from the bytes, so that the same id cannot arrive twice in two spellings
    txid = raw_txid.hex()

    output_index = _whole_number(entry['tx_pos'], 'an output index')

    if not 0 <= output_index <= MAX_OUTPUT_INDEX:
        raise ValueError(f'The server gave {output_index} as an output index')

    amount = _whole_number(entry['value'], 'an amount')

    if not 0 <= amount <= MAX_MONEY_IN_SAT:
        raise ValueError(f'The server gave {amount} as an amount in satoshis')

    return Utxo(txid, output_index, amount, script.full_path(), script.type())


def _electrum_script_hash(script: bytes) -> str:
    """
    Compute the hex-encoded big-endian sha256 hash of a script.
    """
    bytes = bytearray(scripts.sha256(script))
    bytes.reverse()
    return bytes.hex()


async def _electrum_rpc(client: StratumClient, requests: List[Tuple[str, ...]]) -> List:
    """
    Perform an electrum RPC call, using batching if multiple requests are required.
    """
    if len(requests) == 0:
        return []

    if len(requests) == 1:
        request = requests[0]
        response = await client.RPC(*request)
        return [response]

    response = await client.batch_rpc(requests)

    if not isinstance(response, list) or len(response) != len(requests):
        raise ValueError(f'The server answered {len(requests)} requests with {response!r}')

    return response
