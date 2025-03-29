#!/usr/bin/env python3
import unittest
from typing import List, Tuple
from unittest import mock

import coincurve
from bip32 import BIP32

import scanner
import scripts
import transactions
from descriptors import Path
from scripts import ScriptType

# Master key from the BIP32 test vector 1, used wherever a signature is needed
BIP32_TEST_SEED = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

# Destination address from the BIP173 test vectors
DESTINATION = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'


def _master_key() -> BIP32:
    return BIP32.from_seed(BIP32_TEST_SEED)


def _utxo(amount_in_sat: int, script_type: ScriptType = ScriptType.SEGWIT) -> scanner.Utxo:
    txid = '77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb'
    return scanner.Utxo(txid, 1, amount_in_sat, Path("m/84'/0'/0'/0/0"), script_type)


def _signing_digest(tx: transactions.Transaction, index: int, master_key: BIP32) -> bytes:
    """
    Rebuild the digest that was signed for one input, the way the transaction did.
    """
    utxo = tx.inputs[index][0]
    pubkey = master_key.get_pubkey_from_path(utxo.path.to_list())
    script = ScriptType.LEGACY.build_output_script(pubkey)
    inputs = [(u, script if i == index else b'', []) for i, (u, _, _) in enumerate(tx.inputs)]

    if utxo.script_type == ScriptType.LEGACY:
        digest = transactions._serialize_tx(inputs, tx.outputs, include_witness=False)
    else:
        digest = transactions._serialize_tx_for_segwit_signing(index, inputs, tx.outputs)

    digest.extend(transactions.SIGHASH_ALL.to_bytes(4, 'little'))
    return scripts.sha256(scripts.sha256(bytes(digest)))


def _signature_and_pubkey(tx: transactions.Transaction, index: int) -> Tuple[bytes, bytes]:
    """
    Pull the signature and the public key out of a signed input, wherever they were put.
    """
    utxo, script, witness = tx.inputs[index]

    if utxo.script_type == ScriptType.LEGACY:
        signature_length = script[0]
        pubkey_length = script[1 + signature_length]
        return script[1:1 + signature_length], script[2 + signature_length:2 + signature_length + pubkey_length]

    return witness[0], witness[1]


class TestVarint(unittest.TestCase):
    """
    CompactSize encoding, over the four ranges defined by the wire format.
    """

    def test_encodes_a_single_byte_below_the_marker(self) -> None:
        self.assertEqual(transactions._varint(0).hex(), '00')
        self.assertEqual(transactions._varint(0xfc).hex(), 'fc')

    def test_encodes_two_bytes_with_the_fd_marker(self) -> None:
        self.assertEqual(transactions._varint(0xfd).hex(), 'fdfd00')
        self.assertEqual(transactions._varint(0xffff).hex(), 'fdffff')

    def test_encodes_four_bytes_with_the_fe_marker(self) -> None:
        self.assertEqual(transactions._varint(0x1_0000).hex(), 'fe00000100')
        self.assertEqual(transactions._varint(0xffff_ffff).hex(), 'feffffffff')

    def test_encodes_eight_bytes_with_the_ff_marker(self) -> None:
        self.assertEqual(transactions._varint(0x1_0000_0000).hex(), 'ff0000000001000000')

    def test_rejects_a_number_that_does_not_fit(self) -> None:
        with self.assertRaises(ValueError):
            transactions._varint(0x1_0000_0000_0000_0000)


class TestReversed(unittest.TestCase):
    """
    Byte reversal, used to turn a displayed txid into its wire encoding.
    """

    def test_reverses_the_bytes(self) -> None:
        self.assertEqual(transactions._reversed(bytes.fromhex('0102ff')).hex(), 'ff0201')

    def test_leaves_an_empty_array_untouched(self) -> None:
        self.assertEqual(transactions._reversed(b''), b'')


class TestSegwitSigningDigest(unittest.TestCase):
    """
    BIP143 signature digest, checked against the official P2SH-P2WPKH test vector.
    """

    # The vector uses a transaction version, a sequence and a locktime that this codebase holds as
    # module constants, so all three are patched to the values the vector requires
    VECTOR_VERSION = 1
    # The vector shows the sequence as the bytes feffffff, which is this integer little-endian
    VECTOR_SEQUENCE = 0xfffffffe
    VECTOR_LOCKTIME = 0x0000_0492
    VECTOR_TXID = '77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb'
    VECTOR_AMOUNT = 1_000_000_000
    VECTOR_SCRIPT_CODE = bytes.fromhex('76a91479091972186c449eb1ded22b78e40d009bdf008988ac')
    VECTOR_SIGHASH = '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6'

    def test_reproduces_the_bip143_p2sh_p2wpkh_sighash(self) -> None:
        utxo = scanner.Utxo(self.VECTOR_TXID, 1, self.VECTOR_AMOUNT, Path("m/0'"), ScriptType.COMPAT)
        inputs = [(utxo, self.VECTOR_SCRIPT_CODE, [])]
        outputs = [
            (199_996_600, bytes.fromhex('76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac')),
            (800_000_000, bytes.fromhex('76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac')),
        ]

        with mock.patch.object(transactions, 'VERSION', self.VECTOR_VERSION), \
             mock.patch.object(transactions, 'SEQUENCE', self.VECTOR_SEQUENCE), \
             mock.patch.object(transactions, 'LOCKTIME', self.VECTOR_LOCKTIME):
            digest = transactions._serialize_tx_for_segwit_signing(0, inputs, outputs)

        digest.extend(transactions.SIGHASH_ALL.to_bytes(4, 'little'))
        self.assertEqual(scripts.sha256(scripts.sha256(bytes(digest))).hex(), self.VECTOR_SIGHASH)


class TestSerialization(unittest.TestCase):
    """
    Wire format serialization, with and without the witness.
    """

    def test_a_legacy_only_transaction_has_no_segwit_marker(self) -> None:
        tx = transactions.Transaction(_master_key(), [_utxo(100_000, ScriptType.LEGACY)], DESTINATION, 90_000)
        self.assertEqual(tx.to_bytes()[:5].hex(), '0200000001')

    def test_a_segwit_transaction_carries_the_marker_and_flag(self) -> None:
        tx = transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, 90_000)
        self.assertEqual(tx.to_bytes()[4:6].hex(), '0001')

    def test_the_version_is_two_and_the_locktime_is_zero(self) -> None:
        tx = transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, 90_000)
        serialized = tx.to_bytes()
        self.assertEqual(serialized[:4].hex(), '02000000')
        self.assertEqual(serialized[-4:].hex(), '00000000')

    def test_the_txid_is_serialized_in_reverse_byte_order(self) -> None:
        utxo = _utxo(100_000, ScriptType.LEGACY)
        tx = transactions.Transaction(_master_key(), [utxo], DESTINATION, 90_000)
        self.assertIn(transactions._reversed(bytes.fromhex(utxo.txid)), tx.to_bytes())

    def test_dropping_the_witness_shortens_a_segwit_transaction(self) -> None:
        tx = transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, 90_000)
        with_witness = transactions._serialize_tx(tx.inputs, tx.outputs)
        without_witness = transactions._serialize_tx(tx.inputs, tx.outputs, include_witness=False)
        self.assertLess(len(without_witness), len(with_witness))


class TestTransaction(unittest.TestCase):
    """
    Sweep transaction construction.
    """

    def test_rejects_an_unrecognized_destination(self) -> None:
        with self.assertRaises(ValueError):
            transactions.Transaction(_master_key(), [_utxo(100_000)], 'not an address', 90_000)

    def test_rejects_an_amount_below_the_dust_threshold(self) -> None:
        with self.assertRaises(ValueError):
            transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, 545)

    def test_rejects_a_negative_amount(self) -> None:
        # A fee larger than the balance reaches the same guard, since a negative amount is below dust
        with self.assertRaises(ValueError):
            transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, -1_000)

    def test_builds_one_input_per_utxo_and_a_single_output(self) -> None:
        utxos = [_utxo(100_000), _utxo(200_000, ScriptType.LEGACY)]
        tx = transactions.Transaction(_master_key(), utxos, DESTINATION, 250_000)
        self.assertEqual(len(tx.inputs), 2)
        self.assertEqual(len(tx.outputs), 1)

    def test_signs_mixed_input_types_in_a_single_transaction(self) -> None:
        utxos = [_utxo(100_000, t) for t in [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT]]
        tx = transactions.Transaction(_master_key(), utxos, DESTINATION, 250_000)
        self.assertEqual([len(witness) for _, _, witness in tx.inputs], [0, 2, 2])

    def test_virtual_size_is_smaller_than_the_serialized_size_for_segwit(self) -> None:
        tx = transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, 90_000)
        self.assertLess(tx.virtual_size(), len(tx.to_bytes()))

    def test_virtual_size_of_a_single_p2wpkh_input(self) -> None:
        # TODO: this rounds the weight down, while BIP141 defines vsize as the weight rounded up
        tx = transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, 90_000)
        witness = len(transactions._serialize_tx(tx.inputs, tx.outputs))
        base = len(transactions._serialize_tx(tx.inputs, tx.outputs, include_witness=False))
        self.assertEqual(tx.virtual_size(), (3 * base + witness) // 4)

    def test_every_signature_verifies_against_the_pubkey_it_ships_with(self) -> None:
        master_key = _master_key()
        utxos = [_utxo(100_000, t) for t in [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT]]
        tx = transactions.Transaction(master_key, utxos, DESTINATION, 250_000)

        for index in range(len(utxos)):
            signature, pubkey = _signature_and_pubkey(tx, index)
            digest = _signing_digest(tx, index, master_key)
            # The trailing byte of the signature is the sighash type, not part of the DER encoding
            verified = coincurve.PublicKey(pubkey).verify(signature[:-1], digest, hasher=None)
            self.assertTrue(verified, f'input {index} carries a signature its public key does not verify')

    def test_every_signature_ends_with_the_sighash_type(self) -> None:
        utxos = [_utxo(100_000, t) for t in [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT]]
        tx = transactions.Transaction(_master_key(), utxos, DESTINATION, 250_000)

        for index in range(len(utxos)):
            signature, _ = _signature_and_pubkey(tx, index)
            self.assertEqual(signature[-1], transactions.SIGHASH_ALL)

    def test_the_pubkey_shipped_matches_the_one_derived_from_the_path(self) -> None:
        master_key = _master_key()
        tx = transactions.Transaction(master_key, [_utxo(100_000)], DESTINATION, 90_000)

        _, pubkey = _signature_and_pubkey(tx, 0)
        self.assertEqual(pubkey, master_key.get_pubkey_from_path(tx.inputs[0][0].path.to_list()))

    def test_a_legacy_only_transaction_has_the_same_size_and_virtual_size(self) -> None:
        tx = transactions.Transaction(_master_key(), [_utxo(100_000, ScriptType.LEGACY)], DESTINATION, 90_000)
        self.assertEqual(tx.virtual_size(), len(tx.to_bytes()))


if __name__ == '__main__':
    unittest.main()
