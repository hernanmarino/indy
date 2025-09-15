#!/usr/bin/env python3
import unittest
from typing import Dict, List, Set, Tuple

from bip32 import BIP32, HARDENED_INDEX
from mnemonic import Mnemonic

import descriptors
from descriptors import DescriptorScriptIterator, Path, Script, ScriptIterator
import scripts
from scanner import MAX_BATCH_SIZE
from scripts import ScriptType

# Master key from the BIP32 test vector 1
BIP32_TEST_SEED = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

# Derived public keys and addresses from the BIP84 test vectors, for the mnemonic below
BIP84_MNEMONIC = ('abandon abandon abandon abandon abandon abandon '
                  'abandon abandon abandon abandon abandon about')
BIP84_VECTORS = [
    ("m/84'/0'/0'/0/0",
     '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c',
     'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'),
    ("m/84'/0'/0'/0/1",
     '03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77',
     'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g'),
    ("m/84'/0'/0'/1/0",
     '03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6',
     'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el'),
]

# The same mnemonic at the BIP44 path, as each script type spells it. The legacy address is the
# one that mnemonic is published under; the other two were built from that key with base58 and
# bech32 rather than with the code these tests exercise
BIP44_FIRST_ADDRESS_PATH = "m/44'/0'/0'/0/0"
BIP44_ADDRESSES = [
    (ScriptType.LEGACY, '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA'),
    (ScriptType.COMPAT, '3HkzTaFbEMWeJPLyNCNhPyGfZsVLDwdD3G'),
    (ScriptType.SEGWIT, 'bc1qmxrw6qdh5g3ztfcwm0et5l8mvws4eva24kmp8m'),
]

# A descriptor whose path has a variable account, and one whose path does not
VARIABLE_ACCOUNT_PATH = "m/84'/0'/a'/0/i"
FIXED_ACCOUNT_PATH = "m/0'/0/i"


def _master_key() -> BIP32:
    return BIP32.from_seed(BIP32_TEST_SEED)


def _scan(
        used: Set[Tuple[str, str]],
        batch_size: int,
        max_scripts: int,
        address_gap: int = 20,
        account_gap: int = 0
) -> Dict:
    """
    Walk the iterator the way scan_master_key does: ask for a batch of scripts, and only then mark
    the used ones. Marking each script as soon as it is yielded hides the feedback delay.
    """
    iterator = ScriptIterator(_master_key(), address_gap, account_gap)
    yielded: List[Tuple[str, str, int, int]] = []
    found: List[Tuple[str, str]] = []

    while len(yielded) < max_scripts:
        batch = []
        for _ in range(batch_size):
            script = iterator.next_script()
            if not script:
                break
            batch.append(script)

        if not batch:
            break

        for script in batch:
            descriptor = (script.descriptor.path.path, script.type().name)
            yielded.append(descriptor + (script.index, script.account))
            if (script.full_path().path, script.type().name) in used:
                script.set_as_used()
                found.append((script.full_path().path, script.type().name))

    return {
        'terminated': len(yielded) < max_scripts,
        'yielded': len(yielded),
        'repeated_pairs': len(yielded) - len(set(yielded)),
        'found': found,
        'declared': iterator.total_scripts(),
    }


def _walk(max_scripts: int) -> List[Tuple[str, str, int, int]]:
    """
    Every descriptor the iterator yields, with nothing marked as used along the way.
    """
    iterator = ScriptIterator(_master_key(), 20, 0)
    walked = []

    while len(walked) < max_scripts:
        script = iterator.next_script()

        if not script:
            return walked

        walked.append((script.descriptor.path.path, script.type().name, script.index, script.account))

    raise AssertionError(f'The walk did not end within {max_scripts} scripts')


class TestPath(unittest.TestCase):
    """
    Derivation path with optional account and index placeholders.
    """

    def test_detects_a_variable_account(self) -> None:
        self.assertTrue(Path(VARIABLE_ACCOUNT_PATH).has_variable_account())
        self.assertFalse(Path(FIXED_ACCOUNT_PATH).has_variable_account())

    def test_detects_a_variable_index(self) -> None:
        self.assertTrue(Path(VARIABLE_ACCOUNT_PATH).has_variable_index())
        self.assertFalse(Path("m/44'/0'/0'").has_variable_index())

    def test_converts_a_path_into_derivation_indexes(self) -> None:
        self.assertEqual(Path(VARIABLE_ACCOUNT_PATH).to_list(index=7, account=3),
                         [HARDENED_INDEX + 84, HARDENED_INDEX, HARDENED_INDEX + 3, 0, 7])

    def test_ignores_the_account_when_the_path_has_no_placeholder(self) -> None:
        self.assertEqual(Path(FIXED_ACCOUNT_PATH).to_list(index=2, account=0),
                         Path(FIXED_ACCOUNT_PATH).to_list(index=2, account=9))

    def test_fixing_the_account_replaces_only_that_placeholder(self) -> None:
        self.assertEqual(Path(VARIABLE_ACCOUNT_PATH).with_account(5).path, "m/84'/0'/5'/0/i")

    def test_fixing_the_index_replaces_only_that_placeholder(self) -> None:
        self.assertEqual(Path(VARIABLE_ACCOUNT_PATH).with_index(9).path, "m/84'/0'/a'/0/9")

    def test_paths_with_the_same_string_are_equal_and_hash_alike(self) -> None:
        self.assertEqual(Path(FIXED_ACCOUNT_PATH), Path(FIXED_ACCOUNT_PATH))
        self.assertEqual(hash(Path(FIXED_ACCOUNT_PATH)), hash(Path(FIXED_ACCOUNT_PATH)))

    def test_a_path_is_not_equal_to_another_type(self) -> None:
        self.assertNotEqual(Path(FIXED_ACCOUNT_PATH), FIXED_ACCOUNT_PATH)


class TestDerivedScripts(unittest.TestCase):
    """
    Scripts derived along a path, checked against addresses published elsewhere.
    """

    def setUp(self) -> None:
        self.master_key = BIP32.from_seed(Mnemonic('english').to_seed(BIP84_MNEMONIC))

    def test_the_derived_pubkeys_match_the_published_ones(self) -> None:
        for path, pubkey, _ in BIP84_VECTORS:
            derived = self.master_key.get_pubkey_from_path(Path(path).to_list())
            self.assertEqual(derived.hex(), pubkey, f'wrong public key at {path}')

    def test_the_bip44_path_derives_the_addresses_of_all_three_script_types(self) -> None:
        derived = self.master_key.get_pubkey_from_path(Path(BIP44_FIRST_ADDRESS_PATH).to_list())

        for script_type, address in BIP44_ADDRESSES:
            built = script_type.build_output_script(derived)
            self.assertEqual(built, scripts.build_output_script_from_address(address),
                             f'wrong script for {script_type.name}')

    def test_the_derived_scripts_match_the_published_addresses(self) -> None:
        for path, _, address in BIP84_VECTORS:
            derived = self.master_key.get_pubkey_from_path(Path(path).to_list())
            built = ScriptType.SEGWIT.build_output_script(derived)
            self.assertEqual(built, scripts.build_output_script_from_address(address), f'wrong script at {path}')


class TestScript(unittest.TestCase):
    """
    A script produced by a descriptor at a given index and account.
    """

    def setUp(self) -> None:
        self.descriptor = DescriptorScriptIterator(Path(VARIABLE_ACCOUNT_PATH), ScriptType.SEGWIT, 20, 0)
        self.script = self.descriptor.next_script(_master_key())

    def test_reports_the_script_type_of_its_descriptor(self) -> None:
        self.assertIs(self.script.type(), ScriptType.SEGWIT)

    def test_resolves_the_account_and_then_the_index(self) -> None:
        self.assertEqual(self.script.path_with_account().path, "m/84'/0'/0'/0/i")
        self.assertEqual(self.script.full_path().path, "m/84'/0'/0'/0/0")

    def test_the_program_is_a_p2wpkh_output_script(self) -> None:
        self.assertEqual(len(self.script.program), 22)
        self.assertEqual(self.script.program[:2].hex(), '0014')

    def test_marking_it_as_used_reaches_its_descriptor(self) -> None:
        self.script.set_as_used()
        self.assertTrue(self.descriptor.has_priority_scripts())


class TestDescriptorScriptIterator(unittest.TestCase):
    """
    Traversal of a single descriptor.
    """

    def test_a_fresh_descriptor_has_no_priority_scripts(self) -> None:
        descriptor = DescriptorScriptIterator(Path(VARIABLE_ACCOUNT_PATH), ScriptType.SEGWIT, 20, 0)
        self.assertFalse(descriptor.has_priority_scripts())

    def test_the_declared_total_covers_the_whole_index_range(self) -> None:
        descriptor = DescriptorScriptIterator(Path(VARIABLE_ACCOUNT_PATH), ScriptType.SEGWIT, 20, 0)
        self.assertEqual(descriptor.total_scripts, 21)

    def test_a_path_without_an_index_yields_a_single_script(self) -> None:
        descriptor = DescriptorScriptIterator(Path("m/44'/0'/0'"), ScriptType.LEGACY, 20, 0)
        self.assertEqual(descriptor.total_scripts, 1)
        self.assertIsNotNone(descriptor.next_script(_master_key()))
        self.assertIsNone(descriptor.next_script(_master_key()))

    def test_a_used_script_on_a_path_without_an_index_yields_nothing_more(self) -> None:
        # A path with no index level derives one script and one only, so finding it used must not
        # queue indexes that all resolve back to the very same address
        descriptor = DescriptorScriptIterator(Path("m/44'/0'/0'"), ScriptType.LEGACY, 20, 0)
        descriptor.found_used_script(descriptor.next_script(_master_key()))

        self.assertIsNone(descriptor.next_script(_master_key()))

    def test_finding_a_used_script_queues_the_next_gap_of_indexes(self) -> None:
        descriptor = DescriptorScriptIterator(Path(VARIABLE_ACCOUNT_PATH), ScriptType.SEGWIT, 20, 0)
        descriptor.found_used_script(descriptor.next_script(_master_key()))
        self.assertEqual(list(descriptor.priority_pairs[0]), list(range(1, 21)))

    def test_priority_scripts_are_served_before_the_grid(self) -> None:
        descriptor = DescriptorScriptIterator(Path(VARIABLE_ACCOUNT_PATH), ScriptType.SEGWIT, 20, 0)
        descriptor.found_used_script(descriptor.next_script(_master_key()))
        self.assertEqual(descriptor.next_script(_master_key()).index, 1)


class TestScriptIterator(unittest.TestCase):
    """
    Traversal of every descriptor, cycling through them.
    """

    def test_cycles_through_the_descriptors_instead_of_draining_one(self) -> None:
        # A descriptor is a path and a script type, and a path can carry more than one of those
        iterator = ScriptIterator(_master_key(), 20, 0)
        seen = []

        for _ in range(4):
            script = iterator.next_script()
            seen.append((script.descriptor.path.path, script.type().name))

        self.assertEqual(len(set(seen)), 4)

    def test_the_declared_total_is_the_sum_over_all_descriptors(self) -> None:
        iterator = ScriptIterator(_master_key(), 20, 0)
        self.assertEqual(iterator.total_scripts(), sum(d.total_scripts for d in iterator.descriptors))

    def test_one_descriptor_iterator_per_path_and_script_type_pair(self) -> None:
        iterator = ScriptIterator(_master_key(), 20, 0)
        expected = sum(len(types) for types in descriptors.descriptors.values())
        self.assertEqual(len(iterator.descriptors), expected)

    def test_a_used_address_never_makes_the_same_pair_come_out_twice(self) -> None:
        used = {("m/84'/0'/0'/0/0", 'SEGWIT'), ("m/84'/0'/0'/0/1", 'SEGWIT')}

        for batch_size in [1, MAX_BATCH_SIZE]:
            result = _scan(used, batch_size=batch_size, max_scripts=5_000)

            self.assertTrue(result['terminated'], f'batch {batch_size}')
            self.assertEqual(result['repeated_pairs'], 0, f'batch {batch_size}')
            self.assertEqual(result['found'].count(("m/84'/0'/0'/0/1", 'SEGWIT')), 1, f'batch {batch_size}')

    def test_every_used_address_is_reported_once_however_many_are_found(self) -> None:
        used = {(f"m/84'/0'/0'/0/{index}", 'SEGWIT') for index in range(3)}

        for batch_size in [1, MAX_BATCH_SIZE]:
            result = _scan(used, batch_size=batch_size, max_scripts=5_000)

            self.assertTrue(result['terminated'], f'batch {batch_size}')
            self.assertEqual(sorted(result['found']), sorted(used), f'batch {batch_size}')

    def test_the_walk_never_yields_more_than_the_declared_total(self) -> None:
        # The declared total can overshoot once indexes are requeued, which is how the progress bar
        # has always counted; what must hold is that the walk never runs past it
        for batch_size in [1, 2, MAX_BATCH_SIZE]:
            result = _scan({("m/84'/0'/0'/0/0", 'SEGWIT')}, batch_size=batch_size, max_scripts=5_000)

            self.assertTrue(result['terminated'], f'batch {batch_size}')
            self.assertLessEqual(result['yielded'], result['declared'], f'batch {batch_size}')

    def test_a_used_address_on_a_path_without_an_account_terminates(self) -> None:
        # A path with no account level derives the same script whatever the account is, so walking
        # accounts on it would keep finding the same address over and over
        for batch_size in [1, MAX_BATCH_SIZE]:
            result = _scan({("m/0'/0/0", 'LEGACY')}, batch_size=batch_size, max_scripts=3_000)

            self.assertTrue(result['terminated'], f'batch {batch_size}')
            self.assertEqual(result['found'], [("m/0'/0/0", 'LEGACY')], f'batch {batch_size}')

    def test_the_bip44_path_is_scanned_with_every_script_type(self) -> None:
        # CoolWallet S puts P2SH-SegWit on m/44', and Bisq and KoinKeep put SegWit there
        for chain in [0, 1]:
            for script_type in ['LEGACY', 'COMPAT', 'SEGWIT']:
                with self.subTest(chain=chain, script_type=script_type):
                    address = f"m/44'/0'/0'/{chain}/0"
                    result = _scan({(address, script_type)}, batch_size=MAX_BATCH_SIZE, max_scripts=5_000)

                    self.assertTrue(result['terminated'])
                    self.assertEqual(result['found'], [(address, script_type)])

    def test_those_script_types_reach_whatever_account_is_asked_for(self) -> None:
        # The entries this replaces named account 0, so they covered one wallet each and no more.
        # Account 2 is used here because account 1 is now scanned without asking, and a wallet
        # sitting there would be found by the entry for it rather than by the account gap
        for chain in [0, 1]:
            for script_type in ['COMPAT', 'SEGWIT']:
                with self.subTest(chain=chain, script_type=script_type):
                    address = f"m/44'/0'/2'/{chain}/0"
                    result = _scan({(address, script_type)}, batch_size=MAX_BATCH_SIZE,
                                   max_scripts=40_000, account_gap=2)

                    self.assertTrue(result['terminated'])
                    self.assertEqual(result['found'], [(address, script_type)])

    def test_the_second_bip44_account_is_scanned_without_being_asked_for(self) -> None:
        # Bisq and KoinKeep put the wallet on account 1 and leave account 0 empty, so nothing
        # ever expands the account range and the funds sit outside the scan
        for chain in [0, 1]:
            for script_type in ['LEGACY', 'COMPAT', 'SEGWIT']:
                with self.subTest(chain=chain, script_type=script_type):
                    address = f"m/44'/0'/1'/{chain}/0"
                    result = _scan({(address, script_type)}, batch_size=MAX_BATCH_SIZE, max_scripts=5_000)

                    self.assertTrue(result['terminated'])
                    self.assertEqual(result['found'], [(address, script_type)])

    def test_the_third_account_still_waits_to_be_asked_for(self) -> None:
        # Only the account those two wallets name is scanned for free; the rest is what the
        # account gap is for, and Blockchain.com, which numbers accounts freely, needs it
        result = _scan({("m/44'/0'/2'/0/0", 'SEGWIT')}, batch_size=MAX_BATCH_SIZE, max_scripts=5_000)

        self.assertTrue(result['terminated'])
        self.assertEqual(result['found'], [])

    def test_the_paths_an_electrum_standard_wallet_uses_are_scanned(self) -> None:
        # Electrum hangs the addresses of a standard wallet right off the master key, with no
        # purpose or account level in between
        for chain in [0, 1]:
            with self.subTest(chain=chain):
                address = f'm/{chain}/0'
                result = _scan({(address, 'LEGACY')}, batch_size=MAX_BATCH_SIZE, max_scripts=5_000)

                self.assertTrue(result['terminated'])
                self.assertEqual(result['found'], [(address, 'LEGACY')])

    def test_the_paths_under_a_key_of_its_own_carry_every_script_type(self) -> None:
        # What a wallet exports is the key of its account, and its addresses hang off that at
        # m/0/i and m/1/i whichever script type it spends to
        for chain in [0, 1]:
            for script_type in ['LEGACY', 'COMPAT', 'SEGWIT', 'TAPROOT']:
                with self.subTest(chain=chain, script_type=script_type):
                    address = f'm/{chain}/0'
                    result = _scan({(address, script_type)}, batch_size=MAX_BATCH_SIZE, max_scripts=6_000)

                    self.assertTrue(result['terminated'])
                    self.assertEqual(result['found'], [(address, script_type)])

    def test_the_bip86_path_is_scanned_for_taproot(self) -> None:
        # Taproot addresses are what Sparrow, Ledger and Trezor hand out today, and BIP86 is
        # the path every one of them puts them under
        for chain in [0, 1]:
            with self.subTest(chain=chain):
                address = f"m/86'/0'/0'/{chain}/0"
                result = _scan({(address, 'TAPROOT')}, batch_size=MAX_BATCH_SIZE, max_scripts=6_000)

                self.assertTrue(result['terminated'])
                self.assertEqual(result['found'], [(address, 'TAPROOT')])

    def test_the_bip86_path_is_not_scanned_with_the_other_script_types(self) -> None:
        # A purpose says which script type its addresses are, and looking for the other three
        # under BIP86 would be three requests a wallet never paid to, on every index
        walked = {(path, script_type) for path, script_type, _, _ in _walk(max_scripts=60_000)}

        self.assertEqual({script_type for path, script_type in walked if path.startswith("m/86'")},
                         {'TAPROOT'})

    def test_taproot_is_not_looked_for_under_the_purposes_that_predate_it(self) -> None:
        walked = {(path, script_type) for path, script_type, _, _ in _walk(max_scripts=60_000)}
        taproot_paths = {path for path, script_type in walked if script_type == 'TAPROOT'}

        self.assertEqual(taproot_paths, {"m/86'/0'/a'/0/i", "m/86'/0'/a'/1/i", 'm/0/i', 'm/1/i'})

    def test_a_public_key_walks_the_paths_it_can_derive(self) -> None:
        # A hardened level cannot be derived from a public key, so those paths are left out
        # rather than walked into an error
        public = BIP32.from_xpub(_master_key().get_xpub())
        iterator = ScriptIterator(public, 20, 0)

        for descriptor in iterator.descriptors:
            with self.subTest(path=descriptor.path.path):
                self.assertNotIn("'", descriptor.path.path)

    def test_a_public_key_reaches_the_addresses_under_it(self) -> None:
        public = BIP32.from_xpub(_master_key().get_xpub())
        iterator = ScriptIterator(public, 20, 0)
        derived = set()

        while True:
            script = iterator.next_script()
            if script is None:
                break
            derived.add((script.full_path().path, script.type().name))

        for chain in [0, 1]:
            for script_type in ['LEGACY', 'COMPAT', 'SEGWIT']:
                self.assertIn((f'm/{chain}/0', script_type), derived)

    def test_a_private_key_still_walks_all_of_them(self) -> None:
        self.assertGreater(len(ScriptIterator(_master_key(), 20, 0).descriptors),
                           len(ScriptIterator(BIP32.from_xpub(_master_key().get_xpub()), 20, 0).descriptors))

    def test_no_address_is_derived_twice_under_the_same_script_type(self) -> None:
        # Two descriptors that resolve alike would look the same address up twice over
        iterator = ScriptIterator(_master_key(), 20, 0)
        derived = []

        while True:
            script = iterator.next_script()
            if script is None:
                break
            derived.append((script.full_path().path, script.type().name))

        self.assertEqual(len(derived), len(set(derived)))

    def test_a_scan_with_no_used_addresses_terminates(self) -> None:
        result = _scan(used=set(), batch_size=100, max_scripts=5_000)
        self.assertTrue(result['terminated'])
        self.assertEqual(result['yielded'], result['declared'])


if __name__ == '__main__':
    unittest.main()
