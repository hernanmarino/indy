#!/usr/bin/env python3
import hashlib
import math
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


def _weight_of(tx: transactions.Transaction) -> int:
    """
    Compute the weight of a transaction, as three times its base size plus its total size.
    """
    base = len(transactions._serialize_tx(tx.inputs, tx.outputs, include_witness=False))
    total = len(transactions._serialize_tx(tx.inputs, tx.outputs))

    return 3 * base + total


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


def _witnesses_from_the_wire(raw: bytes) -> List[List[bytes]]:
    """
    Read the witnesses a serialized transaction really carries, rather than the ones the
    transaction it was built from still holds in memory.
    """
    reader = transactions._Reader(raw)
    reader.take(4)

    inputs, witness_flag = transactions._read_inputs(reader)
    transactions._read_outputs(reader)

    if not witness_flag:
        return [[] for _ in inputs]

    witnesses = []
    for _ in inputs:
        witnesses.append([reader.take(reader.varint()) for _ in range(reader.varint())])

    reader.take(4)
    reader.done()

    return witnesses


# Two transactions from the chain, with the ids they are known by. The segwit one is the test
# that matters: an id never covers the witness, so a reader that keeps it computes another id
LEGACY_TXID = 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'
LEGACY_RAW = (
    '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e1'
    '6932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc5'
    '6cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b22'
    '25f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee00'
    '00000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f8'
    '2e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
)

SEGWIT_TXID = '0aa80eddc9a0af25709dae5db5f270ac39a9ecf210c2a0bed5b1f9a70c8b0fa5'
SEGWIT_RAW = (
    '01000000000101df11a710eeacd2de1d2d7b14ff78bfc28d519ab28328281426a14b47deb3233c0000000000ffffff000280'
    '38010000000000160014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2f24401000000000016001432bd79747bf33eb54b'
    'a72e00ef0a32b079c5cf7e024830450221009c52cab824dad09f5a6681e36387388e957cbb557594428dc27de06fb794b7f7'
    '02205d0f6a7e6c50ca4883063308cdcfa6f027365d927c6943bf019f3868ed7383710121030863e3f0c53d48e3f005a13820'
    '34da9c78710dc46c5288dcdd6019943557277d00000000'
)


def _reversed_double_sha256(raw: bytes) -> str:
    """
    Hash a transaction the way an id is taken, independently of how the reader does it.
    """
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


class TestReadingTransactions(unittest.TestCase):
    """
    Reading a serialized transaction back, to check what a server says about its outputs.
    """

    def test_a_legacy_transaction_is_read_back_to_its_id(self) -> None:
        txid, _ = transactions.read_transaction(bytes.fromhex(LEGACY_RAW))

        self.assertEqual(txid, LEGACY_TXID)

    def test_a_segwit_transaction_is_read_back_to_its_id(self) -> None:
        # The witness is not part of what an id covers, so it has to be dropped to arrive at one
        txid, _ = transactions.read_transaction(bytes.fromhex(SEGWIT_RAW))

        self.assertEqual(txid, SEGWIT_TXID)

    def test_the_outputs_of_a_legacy_transaction_are_read(self) -> None:
        _, outputs = transactions.read_transaction(bytes.fromhex(LEGACY_RAW))

        self.assertEqual([amount for amount, _ in outputs], [1_000_000_000, 4_000_000_000])
        self.assertTrue(all(script.endswith(b'\xac') for _, script in outputs))

    def test_the_outputs_of_a_segwit_transaction_are_read(self) -> None:
        _, outputs = transactions.read_transaction(bytes.fromhex(SEGWIT_RAW))

        self.assertEqual([amount for amount, _ in outputs], [80_000, 83_186])
        self.assertTrue(all(script.startswith(b'\x00\x14') for _, script in outputs))

    def test_trailing_bytes_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            transactions.read_transaction(bytes.fromhex(LEGACY_RAW) + b'\x00')

    def test_a_transaction_cut_short_is_refused(self) -> None:
        for cut in [0, 4, 10, 60, len(LEGACY_RAW) // 2 - 1]:
            with self.assertRaises(ValueError, msg=cut):
                transactions.read_transaction(bytes.fromhex(LEGACY_RAW)[:cut])

    def test_a_transaction_of_any_version_and_locktime_is_read(self) -> None:
        # Both fixtures from the chain are version 1 with no locktime, which leaves those fields
        # riding on nothing: a reader that ignored them would agree on every test above
        raw = bytearray((2).to_bytes(4, 'little'))
        raw += b'\x01' + b'\xaa' * 32 + (0).to_bytes(4, 'little') + b'\x00' + b'\xff' * 4
        raw += b'\x01' + (1_000).to_bytes(8, 'little') + b'\x01\x51'
        raw += (800_000).to_bytes(4, 'little')

        txid, outputs = transactions.read_transaction(bytes(raw))

        self.assertEqual(txid, _reversed_double_sha256(bytes(raw)))
        self.assertEqual(outputs, [(1_000, b'\x51')])

    def test_counts_that_need_more_than_one_byte_are_read(self) -> None:
        # Neither fixture has a count over 252, so the wider CompactSize encodings ride on nothing
        raw = bytearray((1).to_bytes(4, 'little'))
        raw += b'\x01' + b'\xaa' * 32 + (0).to_bytes(4, 'little') + b'\x00' + b'\xff' * 4
        raw += b'\xfd' + (300).to_bytes(2, 'little')
        raw += b''.join((index + 1).to_bytes(8, 'little') + b'\x01\x51' for index in range(300))
        raw += (0).to_bytes(4, 'little')

        txid, outputs = transactions.read_transaction(bytes(raw))

        self.assertEqual(txid, _reversed_double_sha256(bytes(raw)))
        self.assertEqual(len(outputs), 300)
        self.assertEqual(outputs[299], (300, b'\x51'))

    def test_a_script_longer_than_a_single_byte_count_is_read(self) -> None:
        script = b'\x51' * 300
        raw = bytearray((1).to_bytes(4, 'little'))
        raw += b'\x01' + b'\xaa' * 32 + (0).to_bytes(4, 'little') + b'\x00' + b'\xff' * 4
        raw += b'\x01' + (1_000).to_bytes(8, 'little') + b'\xfd' + (300).to_bytes(2, 'little') + script
        raw += (0).to_bytes(4, 'little')

        _, outputs = transactions.read_transaction(bytes(raw))

        self.assertEqual(outputs, [(1_000, script)])

    def test_something_that_is_no_transaction_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            transactions.read_transaction(b'\xff' * 40)


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


class TestTaprootSigningDigest(unittest.TestCase):
    """
    BIP341 signature digest, checked against the one key path vector that signs with
    SIGHASH_DEFAULT. Its output has a script tree, which the tweak commits to and the digest
    knows nothing about, so the message it hashes is the same one a BIP86 input hashes.
    """

    # The vector's transaction, and what the nine outputs it spends were paying and holding;
    # its sequences differ from input to input, which is why they travel with the inputs here
    VECTOR_VERSION = 2
    VECTOR_LOCKTIME = 500_000_000
    VECTOR_INPUT_INDEX = 4
    VECTOR_SIGHASH = '4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef'
    VECTOR_RAW_TX = (
        '02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000'
        '000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000ffffff'
        'fff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0'
        '689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202'
        'bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc6'
        '6faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c0'
        '9c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619'
        'e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd1'
        '25c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a914'
        '06afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db3'
        '8cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d'
    )
    VECTOR_SPENT_OUTPUTS = [
        ('512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343', 420_000_000),
        ('5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3', 462_000_000),
        ('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac', 294_000_000),
        ('5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e', 504_000_000),
        ('512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605', 630_000_000),
        ('00147dd65592d0ab2fe0d0257d571abf032cd9db93dc', 378_000_000),
        ('512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831', 672_000_000),
        ('5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5', 546_000_000),
        ('512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220', 588_000_000),
    ]

    def _spent_and_outputs(self) -> Tuple[List[Tuple[bytes, int, bytes, int]], List[Tuple[int, bytes]]]:
        """
        Read the vector's transaction back, so the inputs are the ones it really carries.
        """
        reader = transactions._Reader(bytes.fromhex(self.VECTOR_RAW_TX))

        self.assertEqual(int.from_bytes(reader.take(4), 'little'), self.VECTOR_VERSION)

        inputs, _ = transactions._read_inputs(reader)
        outputs = transactions._read_outputs(reader)

        self.assertEqual(int.from_bytes(reader.take(4), 'little'), self.VECTOR_LOCKTIME)
        reader.done()
        self.assertEqual(len(inputs), len(self.VECTOR_SPENT_OUTPUTS))

        spent = [(outpoint, amount, bytes.fromhex(paid), int.from_bytes(sequence, 'little'))
                 for (outpoint, _, sequence), (paid, amount)
                 in zip(inputs, self.VECTOR_SPENT_OUTPUTS)]

        return spent, outputs

    def test_reproduces_the_bip341_key_path_sighash(self) -> None:
        spent, outputs = self._spent_and_outputs()

        with mock.patch.object(transactions, 'VERSION', self.VECTOR_VERSION), \
             mock.patch.object(transactions, 'LOCKTIME', self.VECTOR_LOCKTIME):
            digest = transactions._taproot_sighash(self.VECTOR_INPUT_INDEX, spent, outputs)

        self.assertEqual(digest.hex(), self.VECTOR_SIGHASH)

    def test_every_input_is_committed_to_and_not_just_the_one_being_signed(self) -> None:
        # This is what BIP341 fixes and BIP143 left open: change the amount of another input
        # and the digest has to move, or a signature can be replayed against a lie about it
        spent, outputs = self._spent_and_outputs()

        with mock.patch.object(transactions, 'VERSION', self.VECTOR_VERSION), \
             mock.patch.object(transactions, 'LOCKTIME', self.VECTOR_LOCKTIME):
            for at in range(len(spent)):
                with self.subTest(changed=at):
                    outpoint, amount, paid, sequence = spent[at]
                    moved = list(spent)
                    moved[at] = (outpoint, amount + 1, paid, sequence)

                    self.assertNotEqual(transactions._taproot_sighash(self.VECTOR_INPUT_INDEX, moved, outputs),
                                        bytes.fromhex(self.VECTOR_SIGHASH))

    def test_the_script_each_input_pays_is_committed_to_as_well(self) -> None:
        spent, outputs = self._spent_and_outputs()

        with mock.patch.object(transactions, 'VERSION', self.VECTOR_VERSION), \
             mock.patch.object(transactions, 'LOCKTIME', self.VECTOR_LOCKTIME):
            for at in range(len(spent)):
                with self.subTest(changed=at):
                    outpoint, amount, paid, sequence = spent[at]
                    moved = list(spent)
                    moved[at] = (outpoint, amount, paid[:-1] + bytes([paid[-1] ^ 1]), sequence)

                    self.assertNotEqual(transactions._taproot_sighash(self.VECTOR_INPUT_INDEX, moved, outputs),
                                        bytes.fromhex(self.VECTOR_SIGHASH))


class TestTaprootSigning(unittest.TestCase):
    """
    What a signed taproot input carries, and which key it can be checked against.
    """

    # Two paths off the test seed whose derived keys have points of either parity, since the
    # move onto the output key negates the scalar for one of them and not for the other
    EVEN_PATH = "m/86'/0'/0'/0/0"
    ODD_PATH = "m/86'/0'/0'/0/1"

    def _signed(self, path: str) -> Tuple[transactions.Transaction, bytes]:
        master_key = _master_key()
        utxo = scanner.Utxo('77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb',
                            1, 100_000, Path(path), ScriptType.TAPROOT)

        return (transactions.Transaction(master_key, [utxo], DESTINATION, 90_000),
                master_key.get_pubkey_from_path(Path(path).to_list()))

    def test_the_parities_this_covers_are_both_there(self) -> None:
        # The negation is a branch, and a test that only ever walks one side of it says
        # nothing about the other
        self.assertEqual(_master_key().get_pubkey_from_path(Path(self.EVEN_PATH).to_list())[0], 2)
        self.assertEqual(_master_key().get_pubkey_from_path(Path(self.ODD_PATH).to_list())[0], 3)

    def test_the_signature_checks_against_the_key_the_output_pays(self) -> None:
        # The output pays the tweaked key, so that is the only key a node checks against, and
        # a signature under the derived key verifies against nothing and spends nothing
        for path in [self.EVEN_PATH, self.ODD_PATH]:
            with self.subTest(path=path):
                tx, pubkey = self._signed(path)
                signature = tx.inputs[0][2][0]
                output_key = scripts.taproot_output_key(pubkey[1:])

                self.assertTrue(coincurve.PublicKeyXOnly(output_key)
                                .verify(signature, transactions._taproot_sighash(
                                    0, [(transactions._outpoint_of(tx.inputs[0][0]),
                                         tx.inputs[0][0].amount_in_sat,
                                         ScriptType.TAPROOT.build_output_script(pubkey),
                                         transactions.SEQUENCE)], tx.outputs)))

    def test_the_signature_does_not_check_against_the_derived_key(self) -> None:
        for path in [self.EVEN_PATH, self.ODD_PATH]:
            with self.subTest(path=path):
                tx, pubkey = self._signed(path)
                digest = transactions._taproot_sighash(
                    0, [(transactions._outpoint_of(tx.inputs[0][0]), tx.inputs[0][0].amount_in_sat,
                         ScriptType.TAPROOT.build_output_script(pubkey), transactions.SEQUENCE)],
                    tx.outputs)

                self.assertFalse(coincurve.PublicKeyXOnly(pubkey[1:]).verify(tx.inputs[0][2][0], digest))

    def test_a_taproot_signature_is_64_bytes_with_no_hash_type_after_it(self) -> None:
        # SIGHASH_DEFAULT is said by leaving it out: a 65th byte would be read as another
        # hash type, and a 0x00 one at that, which is the one spelling BIP341 forbids
        for path in [self.EVEN_PATH, self.ODD_PATH]:
            with self.subTest(path=path):
                tx, _ = self._signed(path)

                self.assertEqual(len(tx.inputs[0][2]), 1)
                self.assertEqual(len(tx.inputs[0][2][0]), 64)
                self.assertEqual(tx.inputs[0][1], b'')

    def test_every_taproot_witness_on_the_wire_signs_the_whole_transaction(self) -> None:
        # Three things at once, none of which a one input check in memory can see: that each
        # input is signed over all of them and not just its own, that the signature reaches
        # the bytes that would be broadcast, and that a taproot input sits beside another kind
        master_key = _master_key()
        txid = '77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb'
        utxos = [
            scanner.Utxo(txid, 0, 100_000, Path(self.EVEN_PATH), ScriptType.TAPROOT),
            scanner.Utxo(txid, 1, 200_000, Path(self.ODD_PATH), ScriptType.TAPROOT),
            scanner.Utxo(txid, 2, 300_000, Path("m/84'/0'/0'/0/0"), ScriptType.SEGWIT),
        ]

        tx = transactions.Transaction(master_key, utxos, DESTINATION, 500_000)
        witnesses = _witnesses_from_the_wire(bytes(tx.to_bytes()))
        pubkeys = [master_key.get_pubkey_from_path(utxo.path.to_list()) for utxo in utxos]
        spent = [(transactions._outpoint_of(utxo), utxo.amount_in_sat,
                  utxo.script_type.build_output_script(pubkey), transactions.SEQUENCE)
                 for utxo, pubkey in zip(utxos, pubkeys)]

        self.assertEqual(len(witnesses), len(utxos))

        signed = 0

        for index, (utxo, pubkey) in enumerate(zip(utxos, pubkeys)):
            if utxo.script_type is not ScriptType.TAPROOT:
                continue

            with self.subTest(input=index):
                output_key = scripts.taproot_output_key(pubkey[scripts.X_ONLY_STARTS_AT:])
                digest = transactions._taproot_sighash(index, spent, tx.outputs)

                self.assertEqual(len(witnesses[index]), 1)
                self.assertTrue(coincurve.PublicKeyXOnly(output_key).verify(witnesses[index][0], digest))
                signed += 1

        self.assertEqual(signed, 2)

    def test_the_output_a_taproot_input_pays_is_the_tweaked_one(self) -> None:
        _, pubkey = self._signed(self.EVEN_PATH)
        script = ScriptType.TAPROOT.build_output_script(pubkey)

        self.assertEqual(script[2:], scripts.taproot_output_key(pubkey[1:]))
        self.assertNotEqual(script[2:], pubkey[1:])


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

    def test_virtual_size_rounds_the_weight_up(self) -> None:
        # BIP141 defines vsize as the weight divided by four and rounded up
        tx = transactions.Transaction(_master_key(), [_utxo(100_000)], DESTINATION, 90_000)

        self.assertEqual(tx.virtual_size(), math.ceil(_weight_of(tx) / 4))

    def test_virtual_size_never_understates_the_weight(self) -> None:
        # Understating it by even one byte pays a fee below the rate that was asked for
        for script_type in [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT]:
            tx = transactions.Transaction(_master_key(), [_utxo(100_000, script_type)], DESTINATION, 90_000)

            self.assertGreaterEqual(4 * tx.virtual_size(), _weight_of(tx), script_type.name)

    def test_virtual_size_rounds_up_whatever_the_weight_leaves_over(self) -> None:
        # Mixing input types reaches weights that are one, two and three over a whole virtual byte
        mixes = [
            [ScriptType.LEGACY],
            [ScriptType.COMPAT],
            [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.COMPAT],
            [ScriptType.LEGACY, ScriptType.LEGACY, ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.COMPAT],
        ]
        remainders = set()

        for mix in mixes:
            tx = transactions.Transaction(_master_key(), [_utxo(100_000, t) for t in mix], DESTINATION, 90_000)
            weight = _weight_of(tx)
            remainders.add(weight % 4)

            self.assertEqual(tx.virtual_size(), math.ceil(weight / 4), [t.name for t in mix])

        self.assertIn(1, remainders, 'No mix left a weight one over a whole virtual byte')

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
