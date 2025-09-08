#!/usr/bin/env python3
import asyncio
import hashlib
import getpass
import io
import json
import os
import sys
import tempfile
import unicodedata
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import List, Optional, Tuple
from unittest import mock

from bip32 import BIP32
from connectrum.client import StratumClient
from connectrum.svr_info import ServerInfo
from mnemonic import Mnemonic

import indy
import scanner
from descriptors import Path
from indy import MAX_FEE_RATE
from scripts import ScriptType

# Master private key from the BIP32 test vector 1
BIP32_TEST_XPRIV = ('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv'
                    'NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')

# The public key of that same vector, and the same private key under a SLIP-132 prefix
BIP32_TEST_XPUB = ('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ES'
                   'FjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
BIP32_TEST_ZPRV = ('zprvAWgYBBk7JR8GjzqSzmunMCS7dAbwpYTCs1YUMDXqduMA5JFHZ3iX5s2UkAR6v'
                   'BdcCYYa1S5o1fVLrKsrnpCQ4WpUd6aVUWP1bS2Yy5DoaKv')
BIP32_TEST_ZPUB = ('zpub6jftahH18ngZxUuv6oSniLNrBCSSE1B4EEU59bwTCEt8x6aS6b2mdfLxbS4QS'
                   '53g85SWWP6wexqeer516433gYpZQoJie2tcMYdJ1SYYYAL')

# That same public key with its key data marked 0x01 and 0xff, neither of which is a point parity
BIP32_TEST_XPUB_MARKED_01 = ('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gYxFk5'
                             'nqmbwrSjnkQvUtYydeKpRyanfmc6qmeyusqpnVEF2j8DGn')
BIP32_TEST_XPUB_MARKED_FF = ('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2ghTzpt'
                             'gqt41dxzAMZBiYMF5w2RQPyuXp1yBkzwxbYKEBjawGLZqf')

# Base58Check strings spelled like key data without standing for a key: one 46 bytes long, and
# one the right length whose x coordinate is past the order of the field
SHORT_PAYLOAD = '111111111111111111111111111111111111111111111GPWnLU'
OFF_CURVE_XPUB = ('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ1hr9'
                  'Rwbk95YadvBkQXxzHBSngB8ndpW6QH7zhhsXZ2jHrohi8A')

# Base58Check over ten bytes: too short for the key data to start where an extended key has it
TINY_PAYLOAD = '2fgFdLat59SRaKu9M1a'

# The test vector with ten bytes stuck on the end: a real point sits where one is looked for
PADDED_XPUB = ('EqvLcMFcyzsxd3n8vc3j14D5Hy2rqrhyHwqhPiWia1TPjEQQ4rWquydPDb2XkDSEebJHyT9N'
               'DUExWFPV3vqKcG3UVi15aYm5nB7nm1LrrZqkuT6PkZaCd8maXNVkJ')

# One phrase per wordlist that only the newer library knows, all of them over an entropy of
# zeroes, which is why each is its first word repeated
NEW_WORDLIST_PHRASES = [
    'abdikace ' * 11 + 'agrese',
    'abacate ' * 11 + 'abater',
    'абзац ' * 11 + 'авангард',
    'abajur ' * 11 + 'abdal',
]

# Phrases whose words are not written the way the wordlist writes them, which is the case for
# roughly a third of the Turkish list and an eighth of the Russian one
COMPOSED_PHRASES = [
    ('aforizm bermuda sipariş aktif donanım misafir '
     'anne karşıt aforizm bermuda sipariş alçak'),
    ('бабочка другой служба бред мокрый ограда '
     'вовремя удачный бабочка другой служба букет'),
]

# A server reached over TLS, as every server in the bundled list is
TEST_SERVER = ServerInfo('example.invalid', hostname='example.invalid', ports='s50002')

# Destination address from the BIP173 test vectors
DESTINATION = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'


class Sweep:
    """
    What a sweep did: what the user saw, what was asked of the server, and in which order.
    """

    def __init__(self, output: str, events: List[str], broadcast: List[str]) -> None:
        self.output = output
        self.events = events
        self.broadcast = broadcast
        self.was_asked = 'asked' in events
        self.reached_the_network = bool(broadcast)


def _sweep(quoted_rate: object, balance: int = 1_000_000, answer: Optional[str] = None, **options: object) -> Sweep:
    """
    Run a whole sweep against a server quoting a fee rate, and record everything it did.
    """
    master_key = BIP32.from_seed(bytes.fromhex('000102030405060708090a0b0c0d0e0f'))
    utxo = scanner.Utxo('ab' * 32, 0, balance, Path("m/84'/0'/0'/0/0"), ScriptType.SEGWIT)
    events: List[str] = []
    broadcast: List[str] = []

    class FakeClient:
        """
        Electrum client that quotes a fee rate and records what it is asked to broadcast.
        """

        async def connect(self, *args: object, **kwargs: object) -> None:
            pass

        async def RPC(self, method: str, *params: object) -> object:
            events.append(method)

            if method == 'blockchain.estimatefee':
                return quoted_rate

            if method == 'blockchain.transaction.broadcast':
                broadcast.append(params[0])
                return 'cd' * 32

            raise AssertionError(f'The sweep asked for an unknown method: {method}')

        def close(self) -> None:
            pass

    async def scan(*args: object) -> List[scanner.Utxo]:
        return [utxo]

    def ask(prompt: str) -> str:
        events.append('asked')
        return answer if answer is not None else ''

    output = io.StringIO()
    settings = {'address': DESTINATION, 'fee_rate': None, 'should_broadcast': False}
    settings.update(options)

    with mock.patch.object(indy, 'StratumClient', lambda **kwargs: FakeClient()), \
         mock.patch.object(scanner, 'scan_master_key', scan), \
         mock.patch('builtins.input', ask):
        with redirect_stdout(output):
            asyncio.run(indy.find_utxos(TEST_SERVER, master_key, 20, 0, should_batch=True, **settings))

    return Sweep(output.getvalue(), events, broadcast)


class TestKeyParsing(unittest.TestCase):
    """
    Reading the key a recovery starts from.
    """

    VALID = ('abandon abandon abandon abandon abandon abandon '
             'abandon abandon abandon abandon abandon about')
    BROKEN_CHECKSUM = 'abandon ' * 11 + 'abandon'
    ONE_WORD_OFF = VALID.replace('about', 'abandon')

    def _parse(self, key: str, **options: object) -> object:
        with redirect_stdout(io.StringIO()):
            return indy.parse_key(key, '', **options)

    def test_a_mnemonic_that_checks_out_is_read(self) -> None:
        self.assertIsNotNone(self._parse(self.VALID))

    def test_a_phrase_that_fits_two_wordlists_is_read_all_the_same(self) -> None:
        # Wordlists overlap, and every word of this one is both French and English. Which of the
        # two it is called does not matter: BIP39 turns the words themselves into the seed
        with self.assertRaises(Exception):
            Mnemonic.detect_language(self.BROKEN_CHECKSUM)

        self.assertIsNotNone(self._parse(self.BROKEN_CHECKSUM, allow_invalid_checksum=True))

    def test_a_phrase_from_any_wordlist_is_taken_for_one(self) -> None:
        # Same entropy for every language, so the phrases are fixed rather than drawn at random
        for language in Mnemonic.list_languages():
            with self.subTest(language=language):
                self.assertTrue(indy._is_a_mnemonic(Mnemonic(language).to_mnemonic(bytes(16))))

    def test_a_phrase_written_in_another_form_than_its_wordlist_is_taken_for_one(self) -> None:
        # Turkish and Russian words carry marks that compose two ways, and the wordlist does not
        # spell them the way a phrase arrives
        for phrase in COMPOSED_PHRASES:
            with self.subTest(phrase=phrase.split()[0]):
                self.assertTrue(indy._is_a_mnemonic(phrase))

    def test_a_phrase_written_in_another_form_checks_out_all_the_same(self) -> None:
        # These came out of the library itself, so their checksums are right by construction,
        # and yet it turns them down when asked to read them back
        for phrase in COMPOSED_PHRASES:
            with self.subTest(phrase=phrase.split()[0]):
                self.assertTrue(indy._checksum_matches(phrase))
                self.assertIsNotNone(self._parse(phrase))

    def test_the_checksum_is_read_the_same_way_for_every_wordlist(self) -> None:
        # A phrase the library builds always checks out, at every length BIP39 defines, and
        # these particular one-word substitutions do not: a checksum can always agree by chance
        for language in Mnemonic.list_languages():
            for size in [16, 20, 24, 28, 32]:
                phrase = Mnemonic(language).to_mnemonic(bytes([size]) * size)
                words = phrase.split()

                with self.subTest(language=language, words=len(words)):
                    self.assertTrue(indy._checksum_matches(phrase))

                    elsewhere = Mnemonic(language).wordlist[(size + 1) % 2048]
                    self.assertFalse(indy._checksum_matches(' '.join(words[:-1] + [elsewhere])))

    def test_a_phrase_of_a_length_bip39_does_not_define_is_refused(self) -> None:
        for count in [11, 13, 23, 25]:
            with self.subTest(count=count):
                self.assertFalse(indy._checksum_matches(' '.join(['abandon'] * count)))

    def test_something_spelled_like_words_but_in_no_wordlist_is_not(self) -> None:
        self.assertFalse(indy._is_a_mnemonic('these words are not in any wordlist at all'))
        self.assertFalse(indy._is_a_mnemonic(''))

    def test_the_wordlists_that_wallets_ask_for_are_there(self) -> None:
        # Trezor writes its phrases in Czech, and Portuguese is the other one BIP39 added
        for language in ['czech', 'portuguese']:
            self.assertIn(language, Mnemonic.list_languages())

    def test_a_phrase_from_one_of_those_derives_what_bip39_says_it_should(self) -> None:
        # The seed is PBKDF2 over the words themselves, worked out here without the library, and
        # the passphrase belongs in its salt rather than anywhere else
        for phrase in NEW_WORDLIST_PHRASES:
            for passphrase in ['', 'a spoken passphrase']:
                with self.subTest(phrase=phrase.split()[0], passphrase=passphrase):
                    salt = unicodedata.normalize('NFKD', 'mnemonic' + passphrase).encode()
                    expected = hashlib.pbkdf2_hmac('sha512', unicodedata.normalize('NFKD', phrase).encode(),
                                                   salt, 2048)

                    with redirect_stdout(io.StringIO()):
                        read = indy.parse_key(phrase, passphrase)

                    self.assertEqual(read.master_privkey, BIP32.from_seed(expected).master_privkey)

    def test_a_phrase_in_another_language_is_read(self) -> None:
        for language in ['spanish', 'french', 'japanese', 'italian']:
            self.assertIsNotNone(self._parse(Mnemonic(language).generate(128)), language)

    def test_a_mnemonic_whose_checksum_does_not_check_out_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._parse(self.BROKEN_CHECKSUM)

    def test_one_wrong_word_is_refused_rather_than_read_as_another_wallet(self) -> None:
        # Every word is in the list and the phrase parses, so nothing but the checksum catches this
        with self.assertRaises(ValueError):
            self._parse(self.ONE_WORD_OFF)

    def test_the_refusal_says_what_to_look_at(self) -> None:
        with self.assertRaises(ValueError) as refused:
            self._parse(self.ONE_WORD_OFF)

        message = str(refused.exception).lower()
        self.assertIn('checksum', message)
        self.assertIn('electrum', message)

    def test_a_checksum_can_be_overridden_for_a_phrase_from_elsewhere(self) -> None:
        self.assertIsNotNone(self._parse(self.BROKEN_CHECKSUM, allow_invalid_checksum=True))

    def test_an_extended_key_is_read_without_any_checksum_talk(self) -> None:
        self.assertIsNotNone(self._parse(BIP32_TEST_XPRIV))

    def test_a_public_key_is_not_read_as_a_private_one(self) -> None:
        # Its key data is a point, not a scalar, and taking one for the other invents a wallet
        self.assertIsNone(self._parse(BIP32_TEST_XPUB).master_privkey)

    def test_a_public_key_stands_for_the_key_it_was_exported_from(self) -> None:
        public = self._parse(BIP32_TEST_XPUB)
        private = self._parse(BIP32_TEST_XPRIV)

        self.assertEqual(public.get_pubkey_from_path([0, 0]), private.get_pubkey_from_path([0, 0]))

    def test_a_public_key_under_another_prefix_is_still_read_as_public(self) -> None:
        under_slip132 = self._parse(BIP32_TEST_ZPUB)

        self.assertIsNone(under_slip132.master_privkey)
        self.assertEqual(under_slip132.get_pubkey_from_path([0, 0]),
                         self._parse(BIP32_TEST_XPUB).get_pubkey_from_path([0, 0]))

    def test_a_private_key_under_another_prefix_is_still_read_as_private(self) -> None:
        # SLIP-132 only changes the version bytes, so what the key carries is what tells them apart
        # A derived child stands for the whole key: the chaincode goes into it as much as the scalar
        under_slip132 = self._parse(BIP32_TEST_ZPRV)

        self.assertIsNotNone(under_slip132.master_privkey)
        self.assertEqual(under_slip132.get_pubkey_from_path([0, 0]),
                         self._parse(BIP32_TEST_XPRIV).get_pubkey_from_path([0, 0]))

    def test_key_data_that_is_neither_private_nor_a_point_is_refused(self) -> None:
        for key in [BIP32_TEST_XPUB_MARKED_01, BIP32_TEST_XPUB_MARKED_FF,
                    OFF_CURVE_XPUB, SHORT_PAYLOAD, PADDED_XPUB, TINY_PAYLOAD]:
            with self.subTest(key=key[-8:]):
                with self.assertRaises(ValueError):
                    self._parse(key)

    def test_something_that_is_no_kind_of_key_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._parse('not a key at all')


class TestSecretInput(unittest.TestCase):
    """
    How the key and the passphrase reach the tool.
    """

    def _run(self, argv: List[str], typed: Optional[List[str]] = None) -> Tuple[str, List[str], Tuple[object, ...]]:
        """
        Run main with a given command line, answering any hidden prompt from a list.
        """
        answers = list(typed or [])
        prompts: List[str] = []
        captured = []

        def hidden(prompt: str = '') -> str:
            prompts.append(prompt)
            return answers.pop(0) if answers else ''

        async def find_utxos(*args: object) -> None:
            captured.append(args)

        output = io.StringIO()
        asyncio.set_event_loop(None)

        with mock.patch.object(indy, 'find_utxos', find_utxos), \
             mock.patch.object(getpass, 'getpass', hidden), \
             mock.patch.object(sys, 'argv', ['indy.py'] + argv):
            with redirect_stdout(output):
                indy.main()

        return output.getvalue(), prompts, captured[0] if captured else ()

    def test_a_key_left_off_the_command_line_is_asked_for(self) -> None:
        output, prompts, _ = self._run(['--host', 'example.invalid'], typed=[BIP32_TEST_XPRIV])

        self.assertEqual(len(prompts), 1)
        self.assertIn('Read master private key', output)

    def test_a_secret_on_the_command_line_still_works_but_is_warned_about(self) -> None:
        output, prompts, _ = self._run([TestKeyParsing.VALID, '--host', 'example.invalid'])

        self.assertEqual(prompts, [])
        self.assertIn('history', output)

    def test_something_that_only_looks_like_a_public_key_still_warns(self) -> None:
        # The exemption is for a key that really decodes, not for anything spelled like one
        output = io.StringIO()

        with redirect_stdout(output):
            indy._read_key('xpub-not-really-a-key')

        self.assertIn('history', output.getvalue())

    def test_a_private_key_on_the_command_line_is_warned_about(self) -> None:
        # The exemption is for public keys, and an extended private key is spelled much like one
        for key in [BIP32_TEST_XPRIV, BIP32_TEST_ZPRV]:
            with self.subTest(key=key[:4]):
                output = io.StringIO()

                with redirect_stdout(output):
                    indy._read_key(key)

                self.assertIn('history', output.getvalue())

    def test_only_something_that_really_is_a_public_key_draws_no_warning(self) -> None:
        # Spelling the marker of a point is not standing for one, and neither buys the exemption
        for key in [SHORT_PAYLOAD, OFF_CURVE_XPUB, PADDED_XPUB, TINY_PAYLOAD]:
            with self.subTest(key=key[-8:]):
                output = io.StringIO()

                with redirect_stdout(output):
                    indy._read_key(key)

                self.assertIn('history', output.getvalue())

    def test_a_public_key_on_the_command_line_draws_no_warning(self) -> None:
        public = ('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ES'
                  'FjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
        output, _, _ = self._run([public, '--host', 'example.invalid'])

        self.assertNotIn('history', output)

    def test_a_passphrase_can_be_asked_for_instead_of_typed(self) -> None:
        _, prompts, _ = self._run(['--ask-passphrase', '--host', 'example.invalid'],
                                  typed=[BIP32_TEST_XPRIV, 'a secret'])

        self.assertEqual(len(prompts), 2)

    def test_the_passphrase_option_will_not_go_without_a_value(self) -> None:
        # Were it to take an optional value, it would swallow the key standing next to it
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                self._run(['--passphrase', '--host', 'example.invalid'])

    def test_asking_for_the_passphrase_leaves_the_key_where_it_is(self) -> None:
        mnemonic = TestKeyParsing.VALID
        _, prompts, arguments = self._run([mnemonic, '--ask-passphrase', '--host', 'example.invalid'],
                                          typed=['a spoken passphrase'])

        with redirect_stdout(io.StringIO()):
            expected = indy.parse_key(mnemonic, 'a spoken passphrase')

        self.assertEqual(len(prompts), 1)
        self.assertEqual(arguments[1].get_master_xpriv(), expected.get_master_xpriv())

    def test_the_two_ways_of_giving_a_passphrase_are_alternatives(self) -> None:
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                self._run([BIP32_TEST_XPRIV, '--passphrase', 'one', '--ask-passphrase'])

    def test_the_checksum_override_reaches_the_derivation(self) -> None:
        broken = TestKeyParsing.BROKEN_CHECKSUM

        with self.assertRaises(ValueError):
            self._run([broken, '--host', 'example.invalid'])

        _, _, arguments = self._run([broken, '--allow-invalid-checksum', '--host', 'example.invalid'])

        self.assertTrue(arguments)

    def test_a_passphrase_that_looks_like_a_public_key_is_still_a_secret(self) -> None:
        output, _, _ = self._run([BIP32_TEST_XPRIV, '--passphrase', 'xpub-but-still-secret',
                                  '--host', 'example.invalid'])

        self.assertIn('history', output)

    def test_a_passphrase_on_the_command_line_is_warned_about(self) -> None:
        output, _, _ = self._run([BIP32_TEST_XPRIV, '--passphrase', 'a secret', '--host', 'x.invalid'])

        self.assertIn('history', output)


class TestDestinationAddress(unittest.TestCase):
    """
    When the destination address is looked at, and what a bad one costs.
    """

    # Some of the strings a sweep cannot be paid to
    UNPAYABLE_ADDRESSES = ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
                 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
                 '18AV53K',
                 '3QJmnh',
                 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
                 'not an address']

    BECH32M = 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'

    def _run(self, address: Optional[str], key: Optional[str] = BIP32_TEST_XPRIV) -> None:
        """
        Run main with a destination address, recording whether anything was asked or scanned.
        """
        self.reached: List[object] = []
        self.prompts: List[str] = []

        async def find_utxos(*args: object) -> None:
            self.reached.append(args)

        def hidden(prompt: str = '') -> str:
            self.prompts.append(prompt)
            return BIP32_TEST_XPRIV

        argv = ['indy.py', '--host', 'example.invalid']
        argv += [key] if key is not None else []
        argv += ['--address', address] if address is not None else []

        with mock.patch.object(indy, 'find_utxos', find_utxos), \
             mock.patch.object(getpass, 'getpass', hidden), \
             mock.patch.object(sys, 'argv', argv):
            with redirect_stdout(io.StringIO()):
                indy.main()

    def test_an_address_that_cannot_be_paid_stops_the_run_before_it_scans(self) -> None:
        for address in self.UNPAYABLE_ADDRESSES:
            with self.subTest(address=address):
                with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                    self._run(address)

                self.assertEqual(self.reached, [])

    def test_the_refusal_says_what_was_wrong(self) -> None:
        errors = io.StringIO()

        with self.assertRaises(SystemExit), redirect_stderr(errors):
            self._run('not an address')

        self.assertIn('address', errors.getvalue())

    def test_nothing_secret_is_asked_for_an_address_that_cannot_be_paid(self) -> None:
        for address in self.UNPAYABLE_ADDRESSES:
            with self.subTest(address=address):
                with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                    self._run(address, key=None)

                self.assertEqual(self.prompts, [])

    def test_a_bech32m_address_is_a_destination_the_scan_runs_for(self) -> None:
        self._run(self.BECH32M)

        self.assertEqual(len(self.reached), 1)

    def test_a_run_with_no_destination_at_all_still_scans(self) -> None:
        self._run(None)

        self.assertEqual(len(self.reached), 1)


class TestFeeBounds(unittest.TestCase):
    """
    Limits on the fee a sweep is allowed to pay.
    """

    def test_a_rate_the_server_quotes_absurdly_high_is_refused(self) -> None:
        # A server quoting 9.0 BTC/kB hands back 900000 sat/vbyte, which on a whole bitcoin leaves
        # a hundredth of it and gives the rest away
        sweep = _sweep(quoted_rate=9.0, balance=100_000_000)

        self.assertNotIn('sweeps all funds', sweep.output)
        self.assertIn('sat/vbyte', sweep.output)

    def test_a_rate_over_the_ceiling_is_refused_even_when_the_balance_absorbs_it(self) -> None:
        # 5000 sat/vbyte on a whole bitcoin is half a percent of it, so the share cap lets it by and
        # the ceiling on the rate is the only thing left between the funds and the miner
        sweep = _sweep(quoted_rate=0.05, balance=100_000_000)

        self.assertNotIn('sweeps all funds', sweep.output)

    def test_a_rate_given_by_hand_is_held_to_the_same_range(self) -> None:
        for by_hand in [-1, 0, MAX_FEE_RATE + 1, 900_000]:
            sweep = _sweep(quoted_rate=None, fee_rate=by_hand)

            self.assertNotIn('sweeps all funds', sweep.output, f'--fee-rate {by_hand}')

    def test_a_whole_number_too_large_to_weigh_is_refused(self) -> None:
        # An integer this size cannot even be compared against a float without raising
        sweep = _sweep(quoted_rate=10 ** 1000)

        self.assertNotIn('sweeps all funds', sweep.output)

    def test_a_rate_of_zero_is_refused(self) -> None:
        sweep = _sweep(quoted_rate=0.0000001)

        self.assertNotIn('sweeps all funds', sweep.output)

    def test_a_rate_that_is_not_a_number_is_refused(self) -> None:
        for quoted in ['not a rate', None, float('nan'), float('inf')]:
            sweep = _sweep(quoted_rate=quoted)

            self.assertNotIn('sweeps all funds', sweep.output, repr(quoted))

    def test_a_fee_over_the_share_of_the_balance_is_refused(self) -> None:
        # 800 sat/vbyte on a 110 vbyte sweep is 88000 sats, well over a tenth of this balance
        sweep = _sweep(quoted_rate=None, fee_rate=800, balance=200_000)

        self.assertNotIn('sweeps all funds', sweep.output)

    def test_that_fee_goes_through_when_it_is_allowed(self) -> None:
        sweep = _sweep(quoted_rate=None, fee_rate=800, balance=200_000, allow_high_fee=True)

        self.assertIn('sweeps all funds', sweep.output)

    def test_a_rate_of_exactly_the_ceiling_is_allowed(self) -> None:
        # Large enough that the fee at this rate is well under a tenth of it
        sweep = _sweep(quoted_rate=None, fee_rate=MAX_FEE_RATE, balance=10_000_000)

        self.assertIn('sweeps all funds', sweep.output)

    def test_a_fee_of_exactly_the_share_is_allowed(self) -> None:
        # This sweep costs 110 vbytes, so at 10 sat/vbyte the fee is exactly a tenth of 11000
        sweep = _sweep(quoted_rate=None, fee_rate=10, balance=11_000)

        self.assertIn('sweeps all funds', sweep.output)

    def test_a_fee_one_satoshi_over_the_share_is_refused(self) -> None:
        sweep = _sweep(quoted_rate=None, fee_rate=10, balance=10_999)

        self.assertNotIn('sweeps all funds', sweep.output)

    def test_an_ordinary_rate_goes_through(self) -> None:
        sweep = _sweep(quoted_rate=0.0001)

        self.assertIn('sweeps all funds', sweep.output)


class TestSweepSummary(unittest.TestCase):
    """
    What the user is shown before a sweep is transmitted.
    """

    def test_the_summary_names_the_destination_and_the_amounts(self) -> None:
        sweep = _sweep(quoted_rate=0.0001, balance=1_000_000)

        self.assertIn(f'To:    {DESTINATION}', sweep.output)
        self.assertIn('Sends: 998900 sats', sweep.output)
        self.assertIn('Fee:   1100 sats, at 10.00 sat/vbyte', sweep.output)

    def test_the_summary_reports_the_rate_the_transaction_really_pays(self) -> None:
        # The provisional transaction used to size the fee can differ from the signed one by a
        # byte, so the rate printed is the one the final transaction works out to
        sweep = _sweep(quoted_rate=None, fee_rate=1, balance=102_400)

        self.assertIn('Fee:   109 sats, at 0.99 sat/vbyte', sweep.output)

    def test_the_summary_says_what_share_of_the_funds_the_fee_is(self) -> None:
        sweep = _sweep(quoted_rate=0.0001, balance=1_000_000)

        self.assertIn('0.1%', sweep.output)

    def test_nothing_is_asked_when_the_transaction_is_not_broadcast(self) -> None:
        sweep = _sweep(quoted_rate=0.0001)

        self.assertFalse(sweep.was_asked)

    def test_broadcasting_asks_first(self) -> None:
        sweep = _sweep(quoted_rate=0.0001, should_broadcast=True, answer='y')

        self.assertTrue(sweep.was_asked)
        self.assertTrue(sweep.reached_the_network)

    def test_anything_other_than_yes_holds_the_transaction_back(self) -> None:
        for answer in ['', 'n', 'no', 'Y E S', 'yeah']:
            sweep = _sweep(quoted_rate=0.0001, should_broadcast=True, answer=answer)

            self.assertFalse(sweep.reached_the_network, repr(answer))

    def test_yes_in_any_case_goes_ahead(self) -> None:
        for answer in ['y', 'Y', ' y ']:
            sweep = _sweep(quoted_rate=0.0001, should_broadcast=True, answer=answer)

            self.assertTrue(sweep.reached_the_network, repr(answer))

    def test_saying_no_reaches_the_network_with_nothing_at_all(self) -> None:
        sweep = _sweep(quoted_rate=0.0001, should_broadcast=True, answer='n')

        self.assertTrue(sweep.was_asked)
        self.assertEqual(sweep.broadcast, [])

    def test_the_question_comes_before_the_transaction_leaves(self) -> None:
        sweep = _sweep(quoted_rate=0.0001, should_broadcast=True, answer='y')

        self.assertLess(sweep.events.index('asked'),
                        sweep.events.index('blockchain.transaction.broadcast'))

    def test_what_is_broadcast_is_the_transaction_that_was_shown(self) -> None:
        sweep = _sweep(quoted_rate=0.0001, should_broadcast=True, answer='y')

        self.assertEqual(len(sweep.broadcast), 1)
        self.assertIn(sweep.broadcast[0], sweep.output.splitlines())

    def test_the_question_can_be_answered_up_front(self) -> None:
        sweep = _sweep(quoted_rate=0.0001, should_broadcast=True, assume_yes=True)

        self.assertFalse(sweep.was_asked)
        self.assertTrue(sweep.reached_the_network)


class TestPublicKeyScan(unittest.TestCase):
    """
    What a recovery does when all it was given is a public key.
    """

    def _run(self) -> Tuple[str, List[object]]:
        """
        Run a scan from the public key of the test vector, recording any connection attempt.
        """
        connections: List[object] = []
        output = io.StringIO()

        def client(**kwargs: object) -> object:
            connections.append(kwargs)
            raise AssertionError('The scan reached the network with nothing it could look up')

        with mock.patch.object(indy, 'StratumClient', client):
            with redirect_stdout(output):
                asyncio.run(indy.find_utxos(TEST_SERVER, BIP32.from_xpub(BIP32_TEST_XPUB),
                                            20, 0, None, None, False, True))

        return output.getvalue(), connections

    def test_a_public_key_is_turned_down_before_any_server_is_reached(self) -> None:
        _, connections = self._run()

        self.assertEqual(connections, [])

    def test_the_reason_names_what_stands_in_the_way(self) -> None:
        output, _ = self._run()

        self.assertIn('hardened', output)
        self.assertIn('private key', output)

    def test_no_funds_are_claimed_either_way(self) -> None:
        output, _ = self._run()

        self.assertNotIn('Didn\'t find any unspent outputs', output)


class TestServerList(unittest.TestCase):
    """
    The bundled list of Electrum servers.
    """

    def test_no_hostname_is_listed_twice(self) -> None:
        # Whether two names are the same machine is a measurement, not something this can tell
        hosts = [server['host'].lower().rstrip('.') for server in indy._read_servers()]

        self.assertEqual(len(hosts), len(set(hosts)))

    def test_every_server_is_reached_over_tls(self) -> None:
        # Read the way the tool reads them: a port field can name more than one transport, and
        # offering plain TCP alongside TLS leaves the choice to the client
        for server in indy._read_servers():
            reachable_by = ServerInfo(server['host'], hostname=server['host'], ports=server['port'])

            self.assertEqual(reachable_by.protocols, {'s'}, server['host'])

    def test_is_read_from_wherever_the_tool_was_started(self) -> None:
        with tempfile.TemporaryDirectory() as elsewhere:
            self.assertTrue(self._read_servers_from(elsewhere))

    def test_a_decoy_in_the_current_directory_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as elsewhere:
            decoy = [{'host': 'decoy.invalid', 'port': 's50002'}]
            with open(os.path.join(elsewhere, 'servers.json'), 'w') as f:
                json.dump(decoy, f)

            self.assertNotEqual(self._read_servers_from(elsewhere), decoy)

    def test_is_read_through_a_symlink_to_the_tool(self) -> None:
        with tempfile.TemporaryDirectory() as elsewhere:
            link = os.path.join(elsewhere, 'indy.py')
            os.symlink(indy.__file__, link)

            self.assertTrue(self._read_servers_through(link))

    def _read_servers_from(self, directory: str) -> List[dict]:
        previous = os.getcwd()
        os.chdir(directory)
        try:
            return indy._read_servers()
        finally:
            os.chdir(previous)

    def _read_servers_through(self, module_path: str) -> List[dict]:
        with mock.patch.object(indy, '__file__', module_path):
            return self._read_servers_from(os.path.dirname(module_path))

    def test_every_server_declares_a_host_and_a_port(self) -> None:
        for server in indy._read_servers():
            self.assertIn('host', server)
            self.assertIn('port', server)


class TestElectrumProtocol(unittest.TestCase):
    """
    The protocol version the client offers when it connects.
    """

    def test_the_scan_offers_a_range_of_protocol_versions(self) -> None:
        # Demanding a single version shuts out every server that speaks an earlier one
        built = []

        class FakeClient:
            """
            Electrum client that records how it was built and refuses to connect.
            """

            def __init__(self, **kwargs: object) -> None:
                built.append(kwargs)

            async def connect(self, *args: object, **kwargs: object) -> None:
                raise ConnectionError('Not connecting in a test')

        async def scan() -> None:
            with self.assertRaises(ConnectionError):
                await indy.find_utxos(TEST_SERVER, BIP32.from_xpriv(BIP32_TEST_XPRIV),
                                      20, 0, None, None, False, True)

        with mock.patch.object(indy, 'StratumClient', FakeClient):
            with redirect_stdout(io.StringIO()):
                asyncio.run(scan())

        self.assertEqual(built, [{'my_proto_version': indy.ELECTRUM_PROTOCOL_VERSIONS}])

    def test_the_range_starts_below_the_newest_version(self) -> None:
        self.assertEqual(indy.ELECTRUM_PROTOCOL_VERSIONS, ['1.4', '1.4.2'])


class TestFeeRate(unittest.TestCase):
    """
    Conversion of the fee rate an electrum server reports.
    """

    def test_a_kilobyte_is_a_thousand_bytes(self) -> None:
        # The electrum protocol reports BTC per 1000 bytes, not per 1024
        self.assertEqual(indy._fee_rate_in_sat_per_vbyte(0.001), 100)

    def test_the_conversion_scales(self) -> None:
        self.assertEqual(indy._fee_rate_in_sat_per_vbyte(0.00001), 1)
        self.assertEqual(indy._fee_rate_in_sat_per_vbyte(0.01), 1_000)

    def test_a_whole_rate_does_not_lose_a_satoshi_to_binary_floats(self) -> None:
        # Scaling the binary value of 0.00007 lands just under 7, and truncating it gives back 6
        for rate in range(1, 1_001):
            self.assertEqual(indy._fee_rate_in_sat_per_vbyte(rate / 100_000), rate)

    def test_a_fractional_rate_is_truncated(self) -> None:
        self.assertEqual(indy._fee_rate_in_sat_per_vbyte(0.000105), 10)

    def test_the_scan_builds_its_fee_from_the_converted_rate(self) -> None:
        # 0.00007 BTC per thousand bytes is exactly 7 sat/vB, and is one of the rates that a binary
        # float drops a satoshi on, so this covers the conversion and the precision at once
        master_key = BIP32.from_seed(bytes.fromhex('000102030405060708090a0b0c0d0e0f'))
        utxo = scanner.Utxo('ab' * 32, 0, 1_000_000, Path("m/84'/0'/0'/0/0"), ScriptType.SEGWIT)

        class FakeClient:
            """
            Electrum client that quotes a fee rate and nothing else.
            """

            async def connect(self, *args: object, **kwargs: object) -> None:
                pass

            async def RPC(self, method: str, *params: object) -> float:
                assert method == 'blockchain.estimatefee', method
                return 0.00007

            def close(self) -> None:
                pass

        async def scan(*args: object) -> List[scanner.Utxo]:
            return [utxo]

        output = io.StringIO()
        destination = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'

        with mock.patch.object(indy, 'StratumClient', lambda **kwargs: FakeClient()), \
             mock.patch.object(scanner, 'scan_master_key', scan):
            with redirect_stdout(output):
                asyncio.run(indy.find_utxos(TEST_SERVER, master_key, 20, 0, destination, None, False, True))

        self.assertIn('7 sat/vbyte', output.getvalue())


class TestInsecureConnections(unittest.TestCase):
    """
    Turning off the protections around the connection to the server.
    """

    def test_certificates_are_verified_unless_told_otherwise(self) -> None:
        self.assertFalse(self._connection_options([])['disable_cert_verify'])

    def test_the_insecure_flag_turns_verification_off(self) -> None:
        self.assertTrue(self._connection_options(['--insecure'])['disable_cert_verify'])

    def test_plain_tcp_is_refused_on_its_own(self) -> None:
        # It sends every address the scan looks up in the clear, so it is the same choice
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                self._connection_options(['--protocol', 't'])

    def test_plain_tcp_goes_through_when_insecure_is_given(self) -> None:
        self.assertEqual(self._connection_options(['--protocol', 't', '--insecure'])['protocols'], {'t'})

    def test_a_server_offering_both_transports_is_refused(self) -> None:
        # The client picks one of them on its own, so offering both is offering plain TCP
        both = [{'host': 'either.invalid', 'port': 's50002 t50001'}]

        with mock.patch.object(indy, '_read_servers', lambda: both):
            self.assertEqual(self._connection_options([], with_host=False), {})

    def test_a_server_offering_both_transports_goes_through_when_insecure(self) -> None:
        both = [{'host': 'either.invalid', 'port': 's50002 t50001'}]

        with mock.patch.object(indy, '_read_servers', lambda: both):
            self.assertTrue(self._connection_options(['--insecure'], with_host=False))

    def _connection_options(self, flags: List[str], with_host: bool = True) -> dict:
        """
        Run main with a given command line and report how the client was told to connect.
        """
        connected = []

        class FakeClient:
            """
            Electrum client that records how it was asked to connect and goes no further.
            """

            def __init__(self, **kwargs: object) -> None:
                pass

            async def connect(self, server: object, **kwargs: object) -> None:
                connected.append(dict(kwargs, protocols=server.protocols))
                raise ConnectionError('Not connecting in a test')

            def close(self) -> None:
                pass

        command = ['indy.py', BIP32_TEST_XPRIV] + (['--host', 'example.invalid'] if with_host else []) + flags
        asyncio.set_event_loop(None)

        with mock.patch.object(indy, 'StratumClient', FakeClient), mock.patch.object(sys, 'argv', command):
            with redirect_stdout(io.StringIO()):
                try:
                    indy.main()
                except ConnectionError:
                    pass

        return connected[0] if connected else {}


class TestEventLoop(unittest.TestCase):
    """
    The event loop the scan runs on.
    """

    def setUp(self) -> None:
        # asyncio.run leaves no loop configured behind it, so that is the state to restore
        self.addCleanup(asyncio.set_event_loop, None)

    def test_the_scan_starts_with_no_event_loop_configured(self) -> None:
        # Nothing sets up a loop before main runs, which is what breaks on Python 3.14
        started = []

        async def find_utxos(*args: object) -> None:
            started.append(args)

        asyncio.set_event_loop(None)
        argv = ['indy.py', BIP32_TEST_XPRIV, '--host', 'example.invalid']

        with mock.patch.object(indy, 'find_utxos', find_utxos), mock.patch.object(sys, 'argv', argv):
            with redirect_stdout(io.StringIO()):
                indy.main()

        self.assertEqual(len(started), 1)

    def test_the_sweep_flags_reach_the_scan(self) -> None:
        captured = []

        async def find_utxos(*args: object) -> None:
            captured.append(args)

        command = ['indy.py', BIP32_TEST_XPRIV, '--host', 'example.invalid']

        # Named rather than counted from the end, so that another argument does not slip past
        allow_high_fee_at, assume_yes_at = 8, 9

        for flags, allow_high_fee, assume_yes in [([], False, False),
                                                  (['--yes'], False, True),
                                                  (['--allow-high-fee'], True, False),
                                                  (['--yes', '--allow-high-fee'], True, True)]:
            captured.clear()
            asyncio.set_event_loop(None)

            with mock.patch.object(indy, 'find_utxos', find_utxos), \
                 mock.patch.object(sys, 'argv', command + flags):
                with redirect_stdout(io.StringIO()):
                    indy.main()

            self.assertEqual(captured[0][allow_high_fee_at], allow_high_fee, flags)
            self.assertEqual(captured[0][assume_yes_at], assume_yes, flags)

    def test_the_electrum_client_takes_the_loop_it_is_built_inside(self) -> None:
        # The client reaches for the running loop in its constructor, so it has to be built from
        # inside the coroutine rather than before the loop exists
        async def build() -> Tuple[StratumClient, asyncio.AbstractEventLoop]:
            return StratumClient(), asyncio.get_running_loop()

        asyncio.set_event_loop(None)
        client, running_loop = asyncio.run(build())

        self.assertIs(client.loop, running_loop)


if __name__ == '__main__':
    unittest.main()
