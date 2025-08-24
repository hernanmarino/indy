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

# Stands in for "answer as usual", so that None itself can be given as an answer
UNCHANGED = object()

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

    def __init__(self, used_hashes: Set[str], unspent: object = UNCHANGED, short_batches: bool = False) -> None:
        self.used_hashes = used_hashes
        self.unspent = unspent
        self.short_batches = short_batches
        self.history = [{'tx_hash': 'ab' * 32, 'height': 700_000}]
        self.closed = False

    async def RPC(self, method: str, *params: Any) -> object:
        return self._answer(method, params[0])

    async def batch_rpc(self, requests: List[Tuple[str, ...]]) -> object:
        answers = [self._answer(method, script_hash) for method, script_hash in requests]

        return answers[:-1] if self.short_batches and answers else answers

    def _answer(self, method: str, script_hash: str) -> object:
        if method not in [self.HISTORY, self.UNSPENT]:
            raise AssertionError(f'The scanner asked for an unknown method: {method}')

        if script_hash not in self.used_hashes:
            return []

        if method == self.HISTORY:
            return self.history

        if self.unspent is not UNCHANGED:
            return self.unspent

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


class TestServerAnswers(unittest.TestCase):
    """
    What the scan accepts from a server it has no reason to trust.
    """

    SOUND = {'tx_hash': 'ab' * 32, 'tx_pos': 0, 'value': 100_000}

    def _scan_with(self, unspent: object, short_batches: bool = False) -> List[scanner.Utxo]:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        client = FakeClient({_script_hash_of(master_key, USED_PATH, USED_TYPE)}, unspent, short_batches)

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, master_key, 20, 0, True)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return asyncio.run(scan())

    def test_a_sound_answer_is_accepted(self) -> None:
        self.assertEqual(len(self._scan_with([self.SOUND])), 1)

    def test_an_amount_that_is_not_a_whole_number_is_refused(self) -> None:
        for value in [100_000.0, '100000', None, True, [100_000]]:
            with self.assertRaises(ValueError, msg=repr(value)):
                self._scan_with([dict(self.SOUND, value=value)])

    def test_an_amount_outside_what_can_exist_is_refused(self) -> None:
        for value in [-1, scanner.MAX_MONEY_IN_SAT + 1]:
            with self.assertRaises(ValueError, msg=repr(value)):
                self._scan_with([dict(self.SOUND, value=value)])

    def test_the_amounts_that_can_exist_are_accepted(self) -> None:
        for value in [1, scanner.MAX_MONEY_IN_SAT]:
            self.assertEqual(len(self._scan_with([dict(self.SOUND, value=value)])), 1, repr(value))

    def test_the_last_possible_output_index_is_accepted(self) -> None:
        self.assertEqual(len(self._scan_with([dict(self.SOUND, tx_pos=scanner.MAX_OUTPUT_INDEX)])), 1)

    def test_an_output_worth_nothing_is_passed_over_rather_than_fatal(self) -> None:
        # Valid by consensus and worth nothing to a sweep, so it must not sink the whole recovery
        found = self._scan_with([dict(self.SOUND, value=0),
                                 dict(self.SOUND, tx_pos=1, value=50_000)])

        self.assertEqual([utxo.amount_in_sat for utxo in found], [50_000])

    def test_more_money_than_exists_in_total_is_refused(self) -> None:
        # Each amount can be the whole supply; what cannot is their sum
        outputs = [dict(self.SOUND, tx_pos=index, value=scanner.MAX_MONEY_IN_SAT) for index in range(3)]

        with self.assertRaises(ValueError):
            self._scan_with(outputs)

    def test_one_transaction_id_spelled_two_ways_is_still_one_output(self) -> None:
        # fromhex ignores case and whitespace, so two spellings serialize to the same outpoint
        with self.assertRaises(ValueError):
            self._scan_with([self.SOUND, dict(self.SOUND, tx_hash=('AB' * 32))])

    def test_a_transaction_id_padded_to_the_right_length_is_refused(self) -> None:
        # Sixty-four characters, but only thirty-one bytes once the spaces are dropped
        with self.assertRaises(ValueError):
            self._scan_with([dict(self.SOUND, tx_hash='ab' * 31 + '  ')])

    def test_a_history_that_is_not_a_list_is_refused(self) -> None:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        client = FakeClient({_script_hash_of(master_key, USED_PATH, USED_TYPE)})
        client.history = {'not': 'a list'}

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, master_key, 20, 0, True)

        with self.assertRaises(ValueError):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                asyncio.run(scan())

    def test_an_output_index_that_makes_no_sense_is_refused(self) -> None:
        for tx_pos in [-1, 1.5, '0', None, True, 0x1_0000_0000]:
            with self.assertRaises(ValueError, msg=repr(tx_pos)):
                self._scan_with([dict(self.SOUND, tx_pos=tx_pos)])

    def test_a_transaction_id_that_is_not_one_is_refused(self) -> None:
        for txid in ['ab' * 31, 'ab' * 33, 'zz' * 32, '', None, 42]:
            with self.assertRaises(ValueError, msg=repr(txid)):
                self._scan_with([dict(self.SOUND, tx_hash=txid)])

    def test_an_answer_that_is_not_a_list_of_entries_is_refused(self) -> None:
        for unspent in [{'tx_hash': 'ab' * 32}, 'unspent', 42, None, [None], ['not an entry']]:
            with self.assertRaises(ValueError, msg=repr(unspent)):
                self._scan_with(unspent)

    def test_a_missing_field_is_refused(self) -> None:
        for missing in ['tx_hash', 'tx_pos', 'value']:
            entry = {field: value for field, value in self.SOUND.items() if field != missing}

            with self.assertRaises(ValueError, msg=missing):
                self._scan_with([entry])

    def test_the_same_output_offered_twice_is_refused_rather_than_quietly_dropped(self) -> None:
        # Spending one output twice builds a transaction the network rejects, and counting it
        # twice inflates the balance; neither is something to paper over by picking one
        with self.assertRaises(ValueError):
            self._scan_with([self.SOUND, dict(self.SOUND)])

    def test_a_batch_answered_short_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._scan_with([self.SOUND], short_batches=True)


if __name__ == '__main__':
    unittest.main()
