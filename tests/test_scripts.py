#!/usr/bin/env python3
import unittest

import scripts
from scripts import ScriptType

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

    def test_rejects_an_unrecognized_string(self) -> None:
        self.assertIsNone(scripts.build_output_script_from_address('not an address'))


if __name__ == '__main__':
    unittest.main()
