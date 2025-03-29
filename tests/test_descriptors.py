#!/usr/bin/env python3
import unittest
from typing import Dict, List, Set, Tuple

from bip32 import BIP32, HARDENED_INDEX
from mnemonic import Mnemonic

import descriptors
from descriptors import DescriptorScriptIterator, Path, Script, ScriptIterator
import scripts
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
    Scripts derived along a path, checked against the BIP84 test vectors.
    """

    def setUp(self) -> None:
        self.master_key = BIP32.from_seed(Mnemonic('english').to_seed(BIP84_MNEMONIC))

    def test_the_derived_pubkeys_match_the_published_ones(self) -> None:
        for path, pubkey, _ in BIP84_VECTORS:
            derived = self.master_key.get_pubkey_from_path(Path(path).to_list())
            self.assertEqual(derived.hex(), pubkey, f'wrong public key at {path}')

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
        iterator = ScriptIterator(_master_key(), 20, 0)
        paths = [iterator.next_script().descriptor.path.path for _ in range(4)]
        self.assertEqual(len(set(paths)), 4)

    def test_the_declared_total_is_the_sum_over_all_descriptors(self) -> None:
        iterator = ScriptIterator(_master_key(), 20, 0)
        self.assertEqual(iterator.total_scripts(), sum(d.total_scripts for d in iterator.descriptors))

    def test_one_descriptor_iterator_per_path_and_script_type_pair(self) -> None:
        iterator = ScriptIterator(_master_key(), 20, 0)
        expected = sum(len(types) for types in descriptors.descriptors.values())
        self.assertEqual(len(iterator.descriptors), expected)

    def test_a_scan_with_no_used_addresses_terminates(self) -> None:
        result = _scan(used=set(), batch_size=100, max_scripts=5_000)
        self.assertTrue(result['terminated'])
        self.assertEqual(result['yielded'], result['declared'])


class TestKnownDefects(unittest.TestCase):
    """
    Current behaviour of two defects in the traversal, kept here so that fixing them shows up as a
    deliberate change. The assertions below describe what the code does today, not what it should do.
    """

    def test_a_used_address_makes_the_same_pair_come_out_twice(self) -> None:
        # TODO: a pair should never be yielded twice; expect no repeats once this is fixed
        used = {("m/84'/0'/0'/0/0", 'SEGWIT'), ("m/84'/0'/0'/0/1", 'SEGWIT')}
        result = _scan(used, batch_size=1, max_scripts=5_000)

        self.assertTrue(result['terminated'])
        self.assertEqual(result['repeated_pairs'], 21)
        self.assertEqual(result['found'].count(("m/84'/0'/0'/0/1", 'SEGWIT')), 2)

    def test_a_used_address_on_a_fixed_account_path_never_finishes(self) -> None:
        # TODO: this scan should terminate; expect a finite walk once this is fixed
        result = _scan({("m/0'/0/0", 'LEGACY')}, batch_size=100, max_scripts=3_000)

        self.assertFalse(result['terminated'])
        self.assertGreater(len(result['found']), 1)


if __name__ == '__main__':
    unittest.main()
