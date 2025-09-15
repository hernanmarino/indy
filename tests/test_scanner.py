#!/usr/bin/env python3
import asyncio
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict, List, Set, Tuple
from unittest import mock

from bip32 import BIP32

import descriptors
import scanner
import transactions
from descriptors import DescriptorScriptIterator, Path
from scripts import ScriptType

# Master key from the BIP32 test vector 1
BIP32_TEST_SEED = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

# Stands in for "answer as usual", so that None itself can be given as an answer
UNCHANGED = object()

# A path the catalogue explores early, so the scan finds it without walking far
USED_PATH = "m/44'/0'/0'/0/0"
USED_TYPE = ScriptType.LEGACY


def _transaction_paying(outputs: List[Tuple[int, bytes]]) -> str:
    """
    Build a transaction whose outputs are the ones given, to back what a server reports.
    """
    raw = bytearray((1).to_bytes(4, 'little'))
    raw += b'\x01' + b'\xaa' * 32 + (0).to_bytes(4, 'little') + b'\x00' + b'\xff' * 4
    raw += bytes([len(outputs)])

    for amount, script in outputs:
        raw += amount.to_bytes(8, 'little') + bytes([len(script)]) + script

    raw += (0).to_bytes(4, 'little')

    return bytes(raw).hex()


def _unspent_paying(program: bytes, amount: int = 100_000, tx_pos: int = 0) -> dict:
    """
    Report an unspent output the way a server would, naming the transaction that really holds it.
    """
    raw = _transaction_paying(_outputs_paying(program, amount, tx_pos))
    txid, _ = transactions.read_transaction(bytes.fromhex(raw))

    return {'tx_hash': txid, 'tx_pos': tx_pos, 'value': amount}


def _outputs_paying(program: bytes, amount: int, tx_pos: int) -> List[Tuple[int, bytes]]:
    """
    Lay out the outputs of a transaction so that the one at that index pays this script.
    """
    return [(546, b'\x51')] * tx_pos + [(amount, program)]


def _program_of(master_key: BIP32, path: str, script_type: ScriptType) -> bytes:
    """
    Build the output script the scan will look for at a given path.
    """
    return script_type.build_output_script(master_key.get_pubkey_from_path(Path(path).to_list()))


def _script_hash_of(master_key: BIP32, path: str, script_type: ScriptType) -> str:
    """
    Compute the scripthash the scanner will ask the server about for a given path.
    """
    return scanner._electrum_script_hash(_program_of(master_key, path, script_type))


def _reported_paths(output: str) -> Set[str]:
    """
    The paths a scan said it found used addresses at, read back off what it printed.
    """
    return {line.split('path=')[1].split(' ')[0] for line in output.splitlines() if 'path=' in line}


def _server_for(master_key: BIP32, **options: object) -> 'FakeClient':
    """
    A server that reports the first address of the scan as used, and backs what it reports.
    """
    return FakeClient({_script_hash_of(master_key, USED_PATH, USED_TYPE)},
                      program=_program_of(master_key, USED_PATH, USED_TYPE), **options)


class FakeClient:
    """
    Electrum server that reports one address as used, holding a single unspent output.
    """

    HISTORY = 'blockchain.scripthash.get_history'
    UNSPENT = 'blockchain.scripthash.listunspent'
    TRANSACTION = 'blockchain.transaction.get'



    def __init__(self, used_hashes: Set[str], unspent: object = UNCHANGED, short_batches: bool = False,
                 spending: object = UNCHANGED, program: bytes = b'') -> None:
        self.used_hashes = used_hashes
        self.program = program
        self.unspent = unspent
        self.short_batches = short_batches
        self.spending = spending
        self.history = [{'tx_hash': 'ab' * 32, 'height': 700_000}]
        self.closed = False

    async def RPC(self, method: str, *params: Any) -> object:
        return self._answer(method, params[0])

    async def batch_rpc(self, requests: List[Tuple[str, ...]]) -> object:
        answers = [self._answer(method, script_hash) for method, script_hash in requests]

        return answers[:-1] if self.short_batches and answers else answers

    def _unspent_entries(self) -> object:
        """
        What this server reports as unspent, made up on the spot unless it was given something.
        """
        if self.unspent is not UNCHANGED:
            return self.unspent

        return [_unspent_paying(self.program)]

    def _transaction_for(self, txid: str) -> str:
        """
        Build a transaction that backs whatever this server said about that id.
        """
        for entry in self._unspent_entries():
            if isinstance(entry, dict) and entry.get('tx_hash') == txid:
                return _transaction_paying(_outputs_paying(self.program, entry['value'], entry['tx_pos']))

        return _transaction_paying([(546, b'\x51')])

    def _answer(self, method: str, script_hash: str) -> object:
        if method == self.TRANSACTION:
            return self.spending if self.spending is not UNCHANGED else self._transaction_for(script_hash)

        if method not in [self.HISTORY, self.UNSPENT]:
            raise AssertionError(f'The scanner asked for an unknown method: {method}')

        if script_hash not in self.used_hashes:
            return []

        if method == self.HISTORY:
            return self.history

        return self._unspent_entries()


class ManyAddressClient(FakeClient):
    """
    Electrum server holding an output at each of several addresses, each backed by a real
    transaction, and counting how often it is asked about any of them.
    """

    def __init__(self, programs: List[bytes]) -> None:
        super().__init__(set())
        self.entry_of: Dict[str, dict] = {}
        self.paid_by: Dict[str, Tuple[bytes, dict]] = {}
        self.asked: Dict[str, int] = {}

        for offset, program in enumerate(programs):
            entry = _unspent_paying(program, amount=100_000 + offset)
            script_hash = scanner._electrum_script_hash(program)

            self.used_hashes.add(script_hash)
            self.entry_of[script_hash] = entry
            self.paid_by[entry['tx_hash']] = (program, entry)

    def _answer(self, method: str, script_hash: str) -> object:
        if method == self.TRANSACTION:
            program, entry = self.paid_by[script_hash]
            return _transaction_paying(_outputs_paying(program, entry['value'], entry['tx_pos']))

        if method not in [self.HISTORY, self.UNSPENT]:
            raise AssertionError(f'The scanner asked for an unknown method: {method}')

        if script_hash not in self.used_hashes:
            return []

        if method == self.HISTORY:
            return self.history

        self.asked[script_hash] = self.asked.get(script_hash, 0) + 1

        return [self.entry_of[script_hash]]


def _run_scan(without_a_terminal: bool) -> Tuple[List[scanner.Utxo], str]:
    """
    Run a whole scan against the fake server, optionally with neither stream on a terminal.
    """
    master_key = BIP32.from_seed(BIP32_TEST_SEED)
    client = _server_for(master_key)
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


class TestRepeatedOutputs(unittest.TestCase):
    """
    What a scan asks and reports when two descriptors spell out the same address.
    """

    # Two entries that derive the very same addresses, which is what a fixed account number and
    # a variable one amount to as soon as the account gap reaches that number
    CATALOGUE: Dict[str, List[ScriptType]] = {
        "m/44'/0'/0'/0/i": [ScriptType.LEGACY],
        "m/44'/0'/a'/0/i": [ScriptType.LEGACY],
        "m/84'/0'/0'/0/i": [ScriptType.SEGWIT],
    }

    # A second address, on a descriptor of its own, used along with the shared one
    OTHER_PATH = "m/84'/0'/0'/0/0"
    OTHER_TYPE = ScriptType.SEGWIT

    def _scan(self, should_batch: bool, also_use_the_other: bool = False) -> Tuple[List[scanner.Utxo],
                                                                                  ManyAddressClient]:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        programs = [_program_of(master_key, USED_PATH, USED_TYPE)]

        if also_use_the_other:
            programs.append(_program_of(master_key, self.OTHER_PATH, self.OTHER_TYPE))

        client = ManyAddressClient(programs)

        with mock.patch.object(descriptors, 'descriptors', self.CATALOGUE):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                utxos = asyncio.run(scanner.scan_master_key(client, master_key, 20, 0, should_batch))

        return utxos, client

    def test_an_output_reached_along_two_paths_is_reported_once(self) -> None:
        # Batched or not, the second descriptor can land in a later round than the first
        for should_batch in [True, False]:
            with self.subTest(should_batch=should_batch):
                utxos, _ = self._scan(should_batch)

                self.assertEqual(len(utxos), 1)

    def test_the_balance_is_what_the_server_holds_and_not_a_multiple_of_it(self) -> None:
        # Counting it twice would offer a sweep of funds that are not there, and spend the same
        # outpoint twice in the transaction that goes out
        for should_batch in [True, False]:
            with self.subTest(should_batch=should_batch):
                utxos, _ = self._scan(should_batch)

                self.assertEqual(sum(utxo.amount_in_sat for utxo in utxos), 100_000)

    def test_an_address_two_descriptors_share_is_asked_about_once(self) -> None:
        for should_batch in [True, False]:
            with self.subTest(should_batch=should_batch):
                _, client = self._scan(should_batch)

                self.assertEqual(max(client.asked.values()), 1)

    def test_the_descriptor_whose_request_is_skipped_still_grows(self) -> None:
        # The fixed entry comes first here, so the variable one is the one skipped. Its account
        # range only reaches account 2 if it went through its own history all the same, which is
        # why the addresses are marked as used before any request is left out
        catalogue = {
            "m/44'/0'/1'/0/i": [ScriptType.LEGACY],
            "m/44'/0'/a'/0/i": [ScriptType.LEGACY],
        }
        shared, beyond = "m/44'/0'/1'/0/0", "m/44'/0'/2'/0/0"
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        client = ManyAddressClient([_program_of(master_key, shared, ScriptType.LEGACY),
                                    _program_of(master_key, beyond, ScriptType.LEGACY)])

        with mock.patch.object(descriptors, 'descriptors', catalogue):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                utxos = asyncio.run(scanner.scan_master_key(client, master_key, 20, 1, True))

        self.assertEqual(sorted(utxo.path.path for utxo in utxos), [shared, beyond])

    def test_every_output_is_credited_to_the_address_it_came_from(self) -> None:
        # Skipping an address shortens the batch, and a response lined up against the wrong
        # script credits its output to a path that cannot sign for it
        for should_batch in [True, False]:
            with self.subTest(should_batch=should_batch):
                utxos, _ = self._scan(should_batch, also_use_the_other=True)

                self.assertEqual(sorted(utxo.path.path for utxo in utxos), [USED_PATH, self.OTHER_PATH])


class TestWhatAPathHangsFrom(unittest.TestCase):
    """
    What the reported path is counted from, which is the key that was handed over and not
    always the master one.
    """

    # Where an account key keeps its addresses, and where an Electrum standard wallet keeps
    # its own: the same two paths, written the same way, off keys three levels apart
    ACCOUNT_PATH = "m/84'/0'/0'"
    SHARED_PATH = 'm/0/0'

    def _scan_finding(self, key: BIP32, path: str) -> str:
        captured = io.StringIO()
        client = FakeClient({_script_hash_of(key, path, USED_TYPE)},
                            program=_program_of(key, path, USED_TYPE))

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, key, 20, 0, True)

        with redirect_stdout(captured), redirect_stderr(captured):
            asyncio.run(scan())

        return captured.getvalue()

    def _account_key(self) -> BIP32:
        root = BIP32.from_seed(BIP32_TEST_SEED)

        return BIP32.from_xpub(root.get_xpub_from_path(Path(self.ACCOUNT_PATH).to_list()))

    def test_the_same_two_addresses_are_not_reported_the_same_way(self) -> None:
        # m/0/0 off a root and m/0/0 off an account key are different addresses. Written the
        # same, whoever copies one down restores the wrong wallet and finds it empty
        root = BIP32.from_seed(BIP32_TEST_SEED)

        self.assertNotEqual(root.get_pubkey_from_path([0, 0]),
                            self._account_key().get_pubkey_from_path([0, 0]))

        from_root = self._scan_finding(root, self.SHARED_PATH)
        from_account = self._scan_finding(self._account_key(), self.SHARED_PATH)

        self.assertNotEqual(_reported_paths(from_root), _reported_paths(from_account))

    def test_a_path_off_a_root_is_written_from_the_master(self) -> None:
        reported = _reported_paths(self._scan_finding(BIP32.from_seed(BIP32_TEST_SEED), self.SHARED_PATH))

        self.assertIn('m/0/i', reported)

    def test_a_path_off_an_account_key_says_so_instead(self) -> None:
        # There is no m above it that this knows, so calling the top of the path m would name
        # a key that was never handed over
        reported = _reported_paths(self._scan_finding(self._account_key(), self.SHARED_PATH))

        self.assertEqual(reported, {'account/0/i'})
        self.assertNotIn('m/0/i', reported)

    def test_what_is_printed_moves_and_what_is_derived_from_does_not(self) -> None:
        # The path an unspent output carries is handed straight back to the key it came from,
        # so renaming what it hangs from for the reader must not reach it
        key = self._account_key()
        client = FakeClient({_script_hash_of(key, self.SHARED_PATH, USED_TYPE)},
                            program=_program_of(key, self.SHARED_PATH, USED_TYPE))

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, key, 20, 0, True)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            utxos = asyncio.run(scan())

        self.assertEqual(utxos[0].path.path, self.SHARED_PATH)
        self.assertEqual(key.get_pubkey_from_path(utxos[0].path.to_list()),
                         key.get_pubkey_from_path([0, 0]))


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
    What the scan accepts as an entry from a server it has no reason to trust.
    """

    SOUND = {'tx_hash': 'ab' * 32, 'tx_pos': 0, 'value': 100_000}

    def setUp(self) -> None:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        descriptor = DescriptorScriptIterator(Path(USED_PATH), USED_TYPE, 20, 0)
        self.script = descriptor.next_script(master_key)

    def _read(self, entry: object) -> scanner.Utxo:
        return scanner._utxo_from(entry, self.script)

    def test_a_sound_entry_is_read(self) -> None:
        self.assertEqual(self._read(self.SOUND).amount_in_sat, 100_000)

    def test_an_amount_that_is_not_a_whole_number_is_refused(self) -> None:
        for value in [100_000.0, '100000', None, True, [100_000]]:
            with self.assertRaises(ValueError, msg=repr(value)):
                self._read(dict(self.SOUND, value=value))

    def test_an_amount_outside_what_can_exist_is_refused(self) -> None:
        for value in [-1, scanner.MAX_MONEY_IN_SAT + 1]:
            with self.assertRaises(ValueError, msg=repr(value)):
                self._read(dict(self.SOUND, value=value))

    def test_the_amounts_that_can_exist_are_read(self) -> None:
        for value in [0, 1, scanner.MAX_MONEY_IN_SAT]:
            self.assertEqual(self._read(dict(self.SOUND, value=value)).amount_in_sat, value)

    def test_an_output_index_that_makes_no_sense_is_refused(self) -> None:
        for tx_pos in [-1, 1.5, '0', None, True, scanner.MAX_OUTPUT_INDEX + 1]:
            with self.assertRaises(ValueError, msg=repr(tx_pos)):
                self._read(dict(self.SOUND, tx_pos=tx_pos))

    def test_the_output_indexes_that_can_exist_are_read(self) -> None:
        for tx_pos in [0, scanner.MAX_OUTPUT_INDEX]:
            self.assertEqual(self._read(dict(self.SOUND, tx_pos=tx_pos)).output_index, tx_pos)

    def test_a_transaction_id_that_is_not_one_is_refused(self) -> None:
        for txid in ['ab' * 31, 'ab' * 33, 'zz' * 32, '', None, 42, 'ab' * 31 + '  ']:
            with self.assertRaises(ValueError, msg=repr(txid)):
                self._read(dict(self.SOUND, tx_hash=txid))

    def test_a_transaction_id_is_read_back_from_its_bytes(self) -> None:
        # So that one id in two spellings cannot pass for two different outputs
        self.assertEqual(self._read(dict(self.SOUND, tx_hash='AB' * 32)).txid, 'ab' * 32)

    def test_an_entry_that_is_not_one_is_refused(self) -> None:
        for entry in [None, 'an entry', 42, ['tx_hash']]:
            with self.assertRaises(ValueError, msg=repr(entry)):
                self._read(entry)

    def test_a_missing_field_is_refused(self) -> None:
        for missing in ['tx_hash', 'tx_pos', 'value']:
            entry = {field: value for field, value in self.SOUND.items() if field != missing}

            with self.assertRaises(ValueError, msg=missing):
                self._read(entry)


class TestWholeAnswers(unittest.TestCase):
    """
    What the scan accepts as a whole answer, over a scan against a server.
    """

    def _scan_with(self, unspent: object = UNCHANGED, short_batches: bool = False) -> List[scanner.Utxo]:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        client = _server_for(master_key, unspent=unspent, short_batches=short_batches)

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, master_key, 20, 0, True)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return asyncio.run(scan())

    def test_a_sound_answer_is_accepted(self) -> None:
        self.assertEqual(len(self._scan_with()), 1)

    def test_an_answer_that_is_not_a_list_of_entries_is_refused(self) -> None:
        for unspent in [{'tx_hash': 'ab' * 32}, 'unspent', 42, None, [None], ['not an entry']]:
            with self.assertRaises(ValueError, msg=repr(unspent)):
                self._scan_with(unspent)

    def test_the_same_output_offered_twice_is_refused_rather_than_quietly_dropped(self) -> None:
        # Spending one output twice builds a transaction the network rejects, and counting it
        # twice inflates the balance; neither is something to paper over by picking one
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        entry = _unspent_paying(_program_of(master_key, USED_PATH, USED_TYPE))

        with self.assertRaises(ValueError):
            self._scan_with([entry, dict(entry)])

    def test_more_money_than_exists_in_total_is_refused(self) -> None:
        # Each amount can be the whole supply; what cannot is their sum
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        program = _program_of(master_key, USED_PATH, USED_TYPE)
        outputs = [_unspent_paying(program, scanner.MAX_MONEY_IN_SAT, index) for index in range(3)]

        with self.assertRaises(ValueError):
            self._scan_with(outputs)

    def test_an_output_worth_nothing_is_passed_over_rather_than_fatal(self) -> None:
        # Valid by consensus and worth nothing to a sweep, so it must not sink the whole recovery
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        program = _program_of(master_key, USED_PATH, USED_TYPE)

        found = self._scan_with([_unspent_paying(program, 0), _unspent_paying(program, 50_000, 1)])

        self.assertEqual([utxo.amount_in_sat for utxo in found], [50_000])

    def test_a_batch_answered_short_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._scan_with(short_batches=True)

    def test_a_history_that_is_not_a_list_is_refused(self) -> None:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        client = _server_for(master_key)
        client.history = {'not': 'a list'}

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, master_key, 20, 0, True)

        with self.assertRaises(ValueError):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                asyncio.run(scan())


class TestAskingForTransactions(unittest.TestCase):
    """
    How the transactions backing the outputs found are asked for.
    """

    def _requests_for(self, outputs: int, should_batch: bool = True) -> List[Tuple[str, ...]]:
        """
        Report every request a scan makes when one address holds that many outputs.
        """
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        program = _program_of(master_key, USED_PATH, USED_TYPE)

        # One transaction paying us at every index, so that the outputs share a transaction
        raw = _transaction_paying([(1_000 + index, program) for index in range(outputs)])
        txid, _ = transactions.read_transaction(bytes.fromhex(raw))
        unspent = [{'tx_hash': txid, 'tx_pos': index, 'value': 1_000 + index} for index in range(outputs)]

        client = _server_for(master_key, unspent=unspent, spending=raw)
        asked = []

        original = client._answer

        def record(method: str, script_hash: str) -> object:
            asked.append((method, script_hash))
            return original(method, script_hash)

        client._answer = record

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, master_key, 20, 0, should_batch)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            asyncio.run(scan())

        return [request for request in asked if request[0] == FakeClient.TRANSACTION]

    def test_one_transaction_is_asked_for_once_however_many_outputs_it_holds(self) -> None:
        # Several outputs of ours in one transaction is one transaction to read back
        self.assertEqual(len(self._requests_for(outputs=4)), 1)

    def test_nothing_is_asked_for_when_nothing_was_found(self) -> None:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        client = _server_for(master_key, unspent=[])
        asked = []
        original = client._answer

        def record(method: str, script_hash: str) -> object:
            asked.append(method)
            return original(method, script_hash)

        client._answer = record

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, master_key, 20, 0, True)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            asyncio.run(scan())

        self.assertNotIn(FakeClient.TRANSACTION, asked)


class TestCheckingWhatWasFound(unittest.TestCase):
    """
    Checking a reported output against the transaction that is said to hold it.
    """

    # A transaction whose second output pays the first address the scan looks at
    SPENDING_TXID = '6507e7e4f0eca959ecbfe1e7129aa20717b545cf346973906534d6fc2a8522c8'
    SPENDING_RAW = ('0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000'
                    'ffffffff0250c30000000000000151a0860100000000001976a914eadbac7f36c37e39361168b7aaee3'
                    'cb24a25312d88ac00000000')
    REPORTED = {'tx_hash': SPENDING_TXID, 'tx_pos': 1, 'value': 100_000}

    def _scan(self, reported: object = UNCHANGED, spending: object = UNCHANGED) -> List[scanner.Utxo]:
        master_key = BIP32.from_seed(BIP32_TEST_SEED)
        unspent = [self.REPORTED] if reported is UNCHANGED else reported
        raw = self.SPENDING_RAW if spending is UNCHANGED else spending
        client = _server_for(master_key, unspent=unspent, spending=raw)

        async def scan() -> List[scanner.Utxo]:
            return await scanner.scan_master_key(client, master_key, 20, 0, True)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return asyncio.run(scan())

    def test_an_output_that_the_transaction_backs_is_accepted(self) -> None:
        found = self._scan()

        self.assertEqual([utxo.amount_in_sat for utxo in found], [100_000])

    def test_an_amount_the_transaction_does_not_back_is_refused(self) -> None:
        # Lying about an amount is how a sweep is made to hand its balance to the miner
        with self.assertRaises(ValueError):
            self._scan(reported=[dict(self.REPORTED, value=100_001)])

    def test_an_output_paying_somewhere_else_is_refused(self) -> None:
        # Same amount at the same index, paying another script: only the script tells them apart
        elsewhere = _transaction_paying([(100_000, b'\x51\x51')])
        txid, _ = transactions.read_transaction(bytes.fromhex(elsewhere))

        with self.assertRaises(ValueError):
            self._scan(reported=[{'tx_hash': txid, 'tx_pos': 0, 'value': 100_000}], spending=elsewhere)

    def test_an_output_index_past_the_end_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._scan(reported=[dict(self.REPORTED, tx_pos=2)])

    def test_a_transaction_that_is_not_the_one_asked_for_is_refused(self) -> None:
        # Otherwise a server can make up a transaction that agrees with whatever it claimed
        with self.assertRaises(ValueError):
            self._scan(reported=[dict(self.REPORTED, tx_hash='cd' * 32)])

    def test_an_answer_that_is_not_a_transaction_is_refused(self) -> None:
        for spending in ['not hex', '', None, 42, 'ab' * 10]:
            with self.assertRaises(ValueError, msg=repr(spending)):
                self._scan(spending=spending)


if __name__ == '__main__':
    unittest.main()
