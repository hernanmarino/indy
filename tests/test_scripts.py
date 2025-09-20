#!/usr/bin/env python3
import unittest

from bip32 import BIP32, HARDENED_INDEX
from mnemonic import Mnemonic

import scripts
from scripts import OP_1, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, ScriptType

# Public keys and their hashes from the BIP143 test vectors
BIP143_P2WPKH_PUBKEY = bytes.fromhex('025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357')
BIP143_P2WPKH_PUBKEY_HASH = bytes.fromhex('1d0f172a0ecb48aee1be1f2687d2963ae33f71a1')

BIP143_P2SH_P2WPKH_PUBKEY = bytes.fromhex('03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873')
BIP143_P2SH_P2WPKH_PUBKEY_HASH = bytes.fromhex('79091972186c449eb1ded22b78e40d009bdf0089')

# Addresses for the public key hashes that BIP143 spends to, with the output scripts it publishes
BIP143_P2PKH_ADDRESS = '1Fyxts6r24DpEieygQiNnWxUdb18ANa5p7'
BIP143_P2PKH_SCRIPT = bytes.fromhex('76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac')

BIP143_P2SH_ADDRESS = '38BW8nqpHSWpkf5sXrQd2xYwvnPJwP59ic'
BIP143_P2SH_SCRIPT = bytes.fromhex('a9144733f37cf4db86fbc2efed2500b4f4e49f31202387')

# Addresses and their output scripts from the BIP173 test vectors
BIP173_P2WPKH_ADDRESS = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
BIP173_P2WPKH_SCRIPT = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')

BIP173_P2WSH_ADDRESS = 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'
BIP173_P2WSH_SCRIPT = bytes.fromhex('00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262')

# The BIP350 vector that a wallet would really hand out today: a version 1, 32 byte program
BIP350_V1_ADDRESS = 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'


# The BIP86 test vectors: the key BIP32 derives, the key the output really pays, and the
# address that key is written as. The first two are the whole of what taproot adds here
BIP86_VECTORS = [
    ('cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115',
     'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c',
     'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'),
    ('83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145',
     'a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb',
     'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh'),
    ('399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef',
     '882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc',
     'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7'),
]

# The BIP86 mnemonic and the account the vectors above hang under
BIP86_MNEMONIC = ('abandon abandon abandon abandon abandon abandon abandon abandon abandon '
                  'abandon abandon about')
BIP86_PATHS = [[0, 0], [0, 1], [1, 0]]
BIP86_PURPOSE = 86

# Mainnet addresses and their output scripts from the BIP350 test vectors
BIP350_VALID_ADDRESSES = [
    ('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', '0014751e76e8199196d454941c45d1b3a323f1433bd6'),
    ('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y',
     '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'),
    ('BC1SW50QGDZ25J', '6002751e'),
    ('bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', '5210751e76e8199196d454941c45d1b3a323'),
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
     '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
]

# Mainnet addresses that BIP350 lists as invalid, each with the rule that turns it down
BIP350_INVALID_ADDRESSES = [
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
     'bech32 checksum on a version 1 address'),
    ('BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
     'bech32 checksum on a version 16 address'),
    ('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
     'bech32m checksum on a version 0 address'),
    ('bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
     'a character outside the charset in the checksum'),
    ('BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
     'a witness version above 16'),
    ('bc1pw5dgrnzv',
     'a witness program of a single byte'),
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
     'a witness program of 41 bytes'),
    ('BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
     'a witness program length that version 0 does not allow'),
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
     'zero padding of more than four bits'),
    ('bc1gmk9yu',
     'no data at all beyond the checksum'),
]


class TestHashHelpers(unittest.TestCase):
    """
    Hashes used to build the output scripts.
    """

    def test_sha256_matches_the_empty_string_digest(self) -> None:
        digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        self.assertEqual(scripts.sha256(b'').hex(), digest)

    def test_ripemd160_matches_the_empty_string_digest(self) -> None:
        self.assertEqual(scripts.ripemd160(b'').hex(), '9c1185a5c5e9fc54612808977ee8f548b2258d31')

    def test_hash160_of_a_pubkey_matches_the_bip143_script_code(self) -> None:
        self.assertEqual(scripts.hash160(BIP143_P2WPKH_PUBKEY), BIP143_P2WPKH_PUBKEY_HASH)


class TestOutputScripts(unittest.TestCase):
    """
    Output scripts built from a public key, for each supported script type.
    """

    def test_legacy_builds_a_p2pkh_script(self) -> None:
        script = ScriptType.LEGACY.build_output_script(BIP143_P2WPKH_PUBKEY)
        self.assertEqual(script.hex(), '76a914' + BIP143_P2WPKH_PUBKEY_HASH.hex() + '88ac')

    def test_segwit_builds_a_p2wpkh_script(self) -> None:
        script = ScriptType.SEGWIT.build_output_script(BIP143_P2WPKH_PUBKEY)
        self.assertEqual(script.hex(), '0014' + BIP143_P2WPKH_PUBKEY_HASH.hex())

    def test_compat_builds_a_p2sh_script_wrapping_the_p2wpkh_program(self) -> None:
        # This is the script the P2SH-P2WPKH vector in BIP143 pays to
        script = ScriptType.COMPAT.build_output_script(BIP143_P2SH_P2WPKH_PUBKEY)
        self.assertEqual(script, BIP143_P2SH_SCRIPT)

    def test_output_scripts_have_the_expected_lengths(self) -> None:
        self.assertEqual(len(ScriptType.LEGACY.build_output_script(BIP143_P2WPKH_PUBKEY)), 25)
        self.assertEqual(len(ScriptType.COMPAT.build_output_script(BIP143_P2WPKH_PUBKEY)), 23)
        self.assertEqual(len(ScriptType.SEGWIT.build_output_script(BIP143_P2WPKH_PUBKEY)), 22)


class TestTaprootOutputKey(unittest.TestCase):
    """
    The key a taproot output pays, which is not the key the path derives.
    """

    def test_the_bip86_path_derives_the_internal_key_of_each_vector(self) -> None:
        # The other tests here start from the published internal key, which leaves the path
        # that reaches it untested. These are the paths the catalogue looks under, and a
        # wrong one finds nothing while every vector below still passes
        root = BIP32.from_seed(Mnemonic.to_seed(BIP86_MNEMONIC))

        # Zipping is what pairs them, and a zip over lists of different lengths walks the
        # shorter one and says nothing, so 'each' has to be worth something first
        self.assertEqual(len(BIP86_VECTORS), len(BIP86_PATHS))

        for (internal, _, _), (chain, index) in zip(BIP86_VECTORS, BIP86_PATHS):
            with self.subTest(chain=chain, index=index):
                path = [BIP86_PURPOSE + HARDENED_INDEX, HARDENED_INDEX, HARDENED_INDEX, chain, index]

                self.assertEqual(root.get_pubkey_from_path(path)[scripts.X_ONLY_STARTS_AT:].hex(), internal)

    def test_the_output_key_is_the_derived_one_tweaked(self) -> None:
        # BIP86 spends by the key alone, so there is no script tree and the tweak commits to
        # the internal key and nothing else. An output paying the internal key is spendable
        # by whoever holds its scalar, but it is not the one BIP86 names, so no wallet built
        # on that standard would ever find it
        for internal, output, _ in BIP86_VECTORS:
            with self.subTest(key=internal[:8]):
                self.assertEqual(scripts.taproot_output_key(bytes.fromhex(internal)).hex(), output)

    def test_the_tweak_is_a_tagged_hash_of_the_internal_key(self) -> None:
        # The tag is hashed and prepended twice, which is what keeps a hash meant for one
        # purpose from being read as one meant for another
        for internal, _, _ in BIP86_VECTORS:
            with self.subTest(key=internal[:8]):
                tag = scripts.sha256(b'TapTweak')
                expected = scripts.sha256(tag + tag + bytes.fromhex(internal))
                self.assertEqual(scripts.tagged_hash('TapTweak', bytes.fromhex(internal)), expected)

    def test_taproot_builds_the_script_the_address_pays(self) -> None:
        # Read back through the address, which is where these vectors can be checked against
        # something this program did not compute
        for internal, _, address in BIP86_VECTORS:
            with self.subTest(address=address[:12]):
                pubkey = bytes([2]) + bytes.fromhex(internal)
                self.assertEqual(ScriptType.TAPROOT.build_output_script(pubkey),
                                 scripts.build_output_script_from_address(address))

    def test_the_prefix_byte_of_the_derived_key_does_not_reach_the_output(self) -> None:
        # BIP340 keys are x only: the two compressed spellings of one point are one taproot
        # output, and taking the 33 bytes as they come would make them two
        for internal, _, _ in BIP86_VECTORS:
            with self.subTest(key=internal[:8]):
                even = ScriptType.TAPROOT.build_output_script(bytes([2]) + bytes.fromhex(internal))
                odd = ScriptType.TAPROOT.build_output_script(bytes([3]) + bytes.fromhex(internal))
                self.assertEqual(even, odd)

    def test_the_script_is_a_witness_version_1_push_of_32_bytes(self) -> None:
        script = ScriptType.TAPROOT.build_output_script(bytes([2]) + bytes.fromhex(BIP86_VECTORS[0][0]))

        self.assertEqual(len(script), 34)
        self.assertEqual(script[0], scripts.OP_1)
        self.assertEqual(script[1], 32)


class TestInputScriptsAndWitnesses(unittest.TestCase):
    """
    Input scripts and witnesses built from a public key and a signature.
    """

    SIGNATURE = bytes.fromhex('30450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be'
                              '022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01')

    def test_legacy_pushes_the_signature_and_the_pubkey(self) -> None:
        script = ScriptType.LEGACY.build_input_script(BIP143_P2WPKH_PUBKEY, self.SIGNATURE)
        expected = (bytes([len(self.SIGNATURE)]) + self.SIGNATURE
                    + bytes([len(BIP143_P2WPKH_PUBKEY)]) + BIP143_P2WPKH_PUBKEY)
        self.assertEqual(script, expected)

    def test_compat_pushes_the_redeem_script(self) -> None:
        script = ScriptType.COMPAT.build_input_script(BIP143_P2SH_P2WPKH_PUBKEY, self.SIGNATURE)
        redeem_script = bytes.fromhex('0014' + BIP143_P2SH_P2WPKH_PUBKEY_HASH.hex())
        self.assertEqual(script, bytes([len(redeem_script)]) + redeem_script)

    def test_segwit_has_an_empty_input_script(self) -> None:
        self.assertEqual(ScriptType.SEGWIT.build_input_script(BIP143_P2WPKH_PUBKEY, self.SIGNATURE), b'')

    def test_legacy_has_an_empty_witness(self) -> None:
        self.assertEqual(ScriptType.LEGACY.build_witness(BIP143_P2WPKH_PUBKEY, self.SIGNATURE), [])

    def test_taproot_has_an_empty_input_script(self) -> None:
        self.assertEqual(ScriptType.TAPROOT.build_input_script(BIP143_P2WPKH_PUBKEY, self.SIGNATURE), b'')

    def test_a_taproot_witness_is_the_signature_and_nothing_else(self) -> None:
        # The output already names the key, so repeating it would only be a byte a fee is
        # paid on, and a second item is what tells the node to look for a script path
        witness = ScriptType.TAPROOT.build_witness(BIP143_P2WPKH_PUBKEY, self.SIGNATURE)

        self.assertEqual(witness, [self.SIGNATURE])

    def test_segwit_and_compat_witnesses_hold_the_signature_and_the_pubkey(self) -> None:
        for script_type in [ScriptType.COMPAT, ScriptType.SEGWIT]:
            witness = script_type.build_witness(BIP143_P2WPKH_PUBKEY, self.SIGNATURE)
            self.assertEqual(witness, [self.SIGNATURE, BIP143_P2WPKH_PUBKEY])


class TestOutputScriptFromAddress(unittest.TestCase):
    """
    Output scripts built from a destination address.
    """

    def test_decodes_a_bech32_p2wpkh_address(self) -> None:
        self.assertEqual(scripts.build_output_script_from_address(BIP173_P2WPKH_ADDRESS), BIP173_P2WPKH_SCRIPT)

    def test_decodes_a_bech32_p2wsh_address(self) -> None:
        self.assertEqual(scripts.build_output_script_from_address(BIP173_P2WSH_ADDRESS), BIP173_P2WSH_SCRIPT)

    def test_decodes_a_base58_p2pkh_address(self) -> None:
        self.assertEqual(scripts.build_output_script_from_address(BIP143_P2PKH_ADDRESS), BIP143_P2PKH_SCRIPT)

    def test_decodes_a_base58_p2sh_address(self) -> None:
        self.assertEqual(scripts.build_output_script_from_address(BIP143_P2SH_ADDRESS), BIP143_P2SH_SCRIPT)

    def test_rejects_an_address_with_a_broken_checksum(self) -> None:
        broken = BIP143_P2PKH_ADDRESS[:-1] + ('8' if BIP143_P2PKH_ADDRESS[-1] != '8' else '9')
        self.assertIsNone(scripts.build_output_script_from_address(broken))

    def test_rejects_a_testnet_address(self) -> None:
        self.assertIsNone(scripts.build_output_script_from_address('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn'))

    def test_rejects_a_bech32_address_from_another_network(self) -> None:
        self.assertIsNone(scripts.build_output_script_from_address('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'))

    def test_rejects_a_base58_string_that_carries_nothing_at_all(self) -> None:
        # Its checksum adds up over an empty payload, so there is not even a header to read
        self.assertIsNone(scripts.build_output_script_from_address('3QJmnh'))

    def test_rejects_a_base58_address_carrying_a_hash_of_the_wrong_length(self) -> None:
        # A script built around this one would compare a 20 byte hash against a single byte
        self.assertIsNone(scripts.build_output_script_from_address('18AV53K'))

    def test_rejects_a_base58_address_carrying_one_byte_too_many(self) -> None:
        # Base58Check over a 21 byte hash: everything about it adds up except what it carries
        self.assertIsNone(scripts.build_output_script_from_address('17sJVfvMWz5aMVTuwpRkaD97VcGzqH2pF78'))

    def test_rejects_an_unrecognized_string(self) -> None:
        self.assertIsNone(scripts.build_output_script_from_address('not an address'))


class TestWritingAnAddress(unittest.TestCase):
    """
    Writing an output script back out as the address a wallet would have shown.
    """

    def test_writes_the_base58_addresses_of_the_bip143_vectors(self) -> None:
        self.assertEqual(scripts.address_of(BIP143_P2PKH_SCRIPT), BIP143_P2PKH_ADDRESS)
        self.assertEqual(scripts.address_of(BIP143_P2SH_SCRIPT), BIP143_P2SH_ADDRESS)

    def test_writes_the_segwit_addresses_of_the_bip173_vectors(self) -> None:
        self.assertEqual(scripts.address_of(BIP173_P2WPKH_SCRIPT), BIP173_P2WPKH_ADDRESS)
        self.assertEqual(scripts.address_of(BIP173_P2WSH_SCRIPT), BIP173_P2WSH_ADDRESS)

    def test_every_valid_bip350_vector_is_written_as_the_vector_spells_it(self) -> None:
        # Those vectors are given in either case; an address is written in lower case
        for address, program in BIP350_VALID_ADDRESSES:
            with self.subTest(address=address[:16]):
                self.assertEqual(scripts.address_of(bytes.fromhex(program)), address.lower())

    def test_what_is_written_reads_back_as_the_script_it_came_from(self) -> None:
        for _, program in BIP350_VALID_ADDRESSES:
            with self.subTest(program=program[:12]):
                script = bytes.fromhex(program)
                self.assertEqual(scripts.build_output_script_from_address(scripts.address_of(script)),
                                 script)

    def test_a_script_that_pays_to_no_address_is_not_given_one(self) -> None:
        # A bare multisig, an OP_RETURN and a truncated push are all valid scripts that no
        # wallet ever displayed as an address, and inventing one for them would be a lie
        for program in [b'\x6a\x04test', b'\x51', b'\x00\x14' + b'\x11' * 19,
                        bytes([OP_1, 32]) + b'\x11' * 31,
                        bytes([OP_DUP, OP_HASH160, 20]) + b'\x11' * 20]:
            with self.subTest(program=program.hex()[:14]):
                self.assertIsNone(scripts.address_of(program))

    def test_a_witness_program_of_a_length_its_version_forbids_has_no_address(self) -> None:
        # The push is consistent here, so this is turned down for the rule BIP141 puts on
        # version nought and not for being malformed, which is what the cases above catch
        self.assertIsNone(scripts.address_of(b'\x00\x15' + b'\x11' * 21))
        self.assertIsNone(scripts.address_of(b'\x00\x02' + b'\x11' * 2))
        self.assertIsNotNone(scripts.address_of(b'\x00\x14' + b'\x11' * 20))

    def test_a_script_shaped_like_a_p2sh_that_does_not_end_like_one_has_no_address(self) -> None:
        # Right length, right prefix, another ending. Reading the hash out of it would name
        # a 3 address for a script that pays to something else entirely
        self.assertIsNone(scripts.address_of(bytes([OP_HASH160, 20]) + b'\x11' * 20
                                             + bytes([OP_EQUALVERIFY])))
        self.assertIsNotNone(scripts.address_of(bytes([OP_HASH160, 20]) + b'\x11' * 20
                                                + bytes([OP_EQUAL])))

    def test_a_push_of_the_wrong_length_is_not_read_as_a_hash(self) -> None:
        # The byte between the opcodes says how much is being pushed. A script whose total
        # length is the legal one but whose push says something else does not put that hash
        # on the stack, and naming it would name an address the script never pays
        self.assertIsNone(scripts.address_of(bytes([OP_DUP, OP_HASH160, 21]) + b'\x11' * 20
                                             + bytes([OP_EQUALVERIFY, OP_CHECKSIG])))
        self.assertIsNone(scripts.address_of(bytes([OP_HASH160, 21]) + b'\x11' * 20
                                             + bytes([OP_EQUAL])))

    def test_a_script_shaped_like_a_p2pkh_that_does_not_end_like_one_has_no_address(self) -> None:
        # Right length, right prefix, and it spends by some other rule. Reading the hash out
        # of it would name an address that script does not pay
        self.assertIsNone(scripts.address_of(bytes([OP_DUP, OP_HASH160, 20]) + b'\x11' * 20
                                             + bytes([OP_EQUALVERIFY, OP_EQUAL])))
        self.assertIsNotNone(scripts.address_of(bytes([OP_DUP, OP_HASH160, 20]) + b'\x11' * 20
                                                + bytes([OP_EQUALVERIFY, OP_CHECKSIG])))


class TestSegwitAddresses(unittest.TestCase):
    """
    Output scripts built from the segwit addresses of the BIP350 test vectors.
    """

    def test_every_valid_vector_builds_the_script_it_publishes(self) -> None:
        for address, script in BIP350_VALID_ADDRESSES:
            with self.subTest(address=address):
                self.assertEqual(scripts.build_output_script_from_address(address), bytes.fromhex(script))

    def test_every_invalid_vector_is_turned_down(self) -> None:
        for address, reason in BIP350_INVALID_ADDRESSES:
            with self.subTest(reason=reason):
                self.assertIsNone(scripts.build_output_script_from_address(address))

    def test_a_version_1_address_spends_to_the_version_1_opcode(self) -> None:
        script = scripts.build_output_script_from_address(BIP350_V1_ADDRESS)

        self.assertIsNotNone(script)
        self.assertEqual(script[0], 0x51)

    def test_the_witness_program_is_pushed_whole(self) -> None:
        script = scripts.build_output_script_from_address(BIP350_V1_ADDRESS)

        self.assertEqual(script[1], 32)
        self.assertEqual(len(script), 34)

    def test_a_version_1_address_from_another_network_is_turned_down(self) -> None:
        testnet = 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c'

        self.assertIsNone(scripts.build_output_script_from_address(testnet))

    def test_an_address_in_mixed_case_is_turned_down(self) -> None:
        mixed = BIP350_V1_ADDRESS[:4] + BIP350_V1_ADDRESS[4:].upper()

        self.assertIsNone(scripts.build_output_script_from_address(mixed))

    def test_an_address_whose_prefix_only_ends_in_the_mainnet_one_is_turned_down(self) -> None:
        self.assertIsNone(scripts.build_output_script_from_address('a' + BIP350_V1_ADDRESS))

    def test_a_prefix_with_nothing_behind_it_is_turned_down(self) -> None:
        self.assertIsNone(scripts.build_output_script_from_address('bc1'))

    def test_a_character_from_outside_bech32_that_folds_into_it_is_turned_down(self) -> None:
        # The Kelvin sign lowercases to a plain k, which would otherwise read as a valid address
        kelvin = BIP173_P2WPKH_ADDRESS.upper().replace('K', '\u212a', 1)

        self.assertNotEqual(kelvin, BIP173_P2WPKH_ADDRESS.upper())
        self.assertIsNone(scripts.build_output_script_from_address(kelvin))

    def test_another_prefix_carrying_mainnet_data_is_turned_down(self) -> None:
        # The checksum of this one only adds up when it is read as the mainnet address it was cut from
        self.assertIsNone(scripts.build_output_script_from_address('xy1' + BIP350_V1_ADDRESS[3:]))


if __name__ == '__main__':
    unittest.main()
