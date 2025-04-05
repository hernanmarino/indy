#!/usr/bin/env python3
import asyncio
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, List, Set, Tuple

from bip32 import BIP32

import scanner
from descriptors import Path
from scripts import ScriptType

# Master key from the BIP32 test vector 1
BIP32_TEST_SEED = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

# A path the catalogue explores early, so the scan finds it without walking far
USED_PATH = "m/44'/0'/0'/0/0"
USED_TYPE = ScriptType.LEGACY


def _script_hash_of(master_key: BIP32, path: str, script_type: ScriptType) -> str:
    """
    Compute the scripthash the scanner will ask the server about for a given path.
    """
    pubkey = master_key.get_pubkey_from_path(Path(path).to_list())
    return scanner._electrum_script_hash(script_type.build_output_script(pubkey))


class FakeClient:
    """
    Electrum server that reports one address as used, holding a single unspent output.
    """

    HISTORY = 'blockchain.scripthash.get_history'
    UNSPENT = 'blockchain.scripthash.listunspent'

    def __init__(self, used_hashes: Set[str]) -> None:
        self.used_hashes = used_hashes
        self.closed = False

    async def RPC(self, method: str, *params: Any) -> List:
        return self._answer(method, params[0])

    async def batch_rpc(self, requests: List[Tuple[str, ...]]) -> List:
        return [self._answer(method, script_hash) for method, script_hash in requests]

    def _answer(self, method: str, script_hash: str) -> List:
        if method not in [self.HISTORY, self.UNSPENT]:
            raise AssertionError(f'The scanner asked for an unknown method: {method}')

        if script_hash not in self.used_hashes:
            return []

        if method == self.HISTORY:
            return [{'tx_hash': 'ab' * 32, 'height': 700_000}]

        return [{'tx_hash': 'ab' * 32, 'tx_pos': 0, 'value': 100_000}]


def _run_scan(without_a_terminal: bool) -> Tuple[List[scanner.Utxo], str]:
    """
    Run a whole scan against the fake server, optionally with neither stream on a terminal.
    """
    master_key = BIP32.from_seed(BIP32_TEST_SEED)
    client = FakeClient({_script_hash_of(master_key, USED_PATH, USED_TYPE)})
    captured = io.StringIO()

    async def scan() -> List[scanner.Utxo]:
        return await scanner.scan_master_key(client, master_key, 20, 0, True)

    if without_a_terminal:
        with redirect_stdout(captured), redirect_stderr(captured):
            utxos = asyncio.run(scan())
    else:
        with redirect_stdout(captured):
            utxos = asyncio.run(scan())

    return utxos, captured.getvalue()


class TestScanWithoutATerminal(unittest.TestCase):
    """
    A scan whose output is redirected, which is what happens under nohup or in CI.
    """

    def test_finding_an_address_does_not_break_when_there_is_no_terminal(self) -> None:
        utxos, _ = _run_scan(without_a_terminal=True)

        self.assertEqual(len(utxos), 1)
        self.assertEqual(utxos[0].amount_in_sat, 100_000)

    def test_the_findings_are_reported_even_without_a_terminal(self) -> None:
        _, output = _run_scan(without_a_terminal=True)

        self.assertIn(USED_PATH.rsplit('/', 1)[0], output)
        self.assertIn('100000 sats', output)


class TestScan(unittest.TestCase):
    """
    A scan against a server that reports a single used address.
    """

    def test_finds_the_unspent_output_of_the_used_address(self) -> None:
        utxos, _ = _run_scan(without_a_terminal=False)

        self.assertEqual(len(utxos), 1)
        self.assertEqual(utxos[0].path.path, USED_PATH)
        self.assertIs(utxos[0].script_type, USED_TYPE)

    def test_finds_nothing_when_the_server_reports_no_history(self) -> None:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        captured = io.StringIO()

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(FakeClient(set()), master_key, 20, 0, True)

        with redirect_stdout(captured):
            self.assertEqual(asyncio.run(scan()), [])


if __name__ == '__main__':
    unittest.main()
