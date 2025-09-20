#!/usr/bin/env python3
import argparse
import asyncio
import getpass
import hashlib
import hmac
import json
import math
import os
import random
import unicodedata
from decimal import Decimal
from typing import List, Optional, Tuple

import base58
import coincurve
import connectrum
from bip32 import BIP32, HARDENED_INDEX
from connectrum.client import StratumClient
from connectrum.svr_info import ServerInfo
from mnemonic import Mnemonic

import bip85
import scanner
import scripts
import transactions
from descriptors import ACCOUNT_DEPTH, ROOT_DEPTH, Script

# Offered to the server as a range, since not every server speaks the newest protocol
ELECTRUM_PROTOCOL_VERSIONS = ['1.4', '1.4.2']

SATOSHIS_PER_BITCOIN = 10 ** 8
BYTES_PER_KILOBYTE = 1_000

# What SLIP-132 writes a mainnet key as, none of which the library knows for mainnet. The
# capitalised four say the key spends to a multisig output, which is a wallet whose addresses
# no single key can work out. SLIP-132 names the script type, not the path it hangs from
SLIP132_SINGLE_KEY_VERSIONS = [0x049d_7cb2, 0x049d_7878, 0x04b2_4746, 0x04b2_430c]
SLIP132_COSIGNER_VERSIONS = [0x0295_b43f, 0x0295_b005, 0x02aa_7ed3, 0x02aa_7a99]
SLIP132_MAINNET_VERSIONS = SLIP132_SINGLE_KEY_VERSIONS + SLIP132_COSIGNER_VERSIONS

# The two the library reads, and every way a mainnet key is written. This tool asks mainnet
# servers, builds mainnet addresses and counts BIP48 from the mainnet coin type, so a key of
# any other chain has no place in it
XPUB_VERSION = 0x0488_b21e
XPRIV_VERSION = 0x0488_ade4
MAINNET_VERSIONS = [XPUB_VERSION, XPRIV_VERSION] + SLIP132_MAINNET_VERSIONS
VERSION_LENGTH_IN_BYTES = 4

# The branches BIP48 puts a multisig under, by the script type each one spends to
BIP48_PURPOSE = 48
MAINNET_COIN_TYPE = 0
MULTISIG_ACCOUNT = 0
MULTISIG_BRANCHES = [(1, 'P2SH-P2WSH'), (2, 'P2WSH')]
SCRIPT_TYPE_COLUMN = 10

# Electrum counts from BIP48 only for a BIP39 seed. Its own seeds go elsewhere: a standard one
# makes the root itself the key a cosigner hands over, and a segwit one the branch at m/1'
ELECTRUM_MULTISIG_BRANCH = 1

# Electrum writes its phrases with the same words as BIP39 and tells its own apart by a version
# it works out of them. The two kinds it makes today are a standard wallet and a segwit one; the
# other two are wallets held with a server, which take a multisig this tool does not build
ELECTRUM_VERSION_KEY = b'Seed version'
ELECTRUM_STANDARD_VERSION = '01'
ELECTRUM_SEGWIT_VERSION = '100'
ELECTRUM_TWO_FACTOR_VERSIONS = ['101', '102']
ELECTRUM_COUNTED_TWO_FACTOR_VERSION = '101'
ELECTRUM_SALT = b'electrum'
PBKDF2_ROUNDS = 2048

# Of the two, only the first answers to a word count: Electrum calls it two-factor at twelve
# words, or at twenty and up, and the segwit one at any length
ELECTRUM_TWO_FACTOR_SHORT_LENGTH = 12
ELECTRUM_TWO_FACTOR_LONG_LENGTH = 20

# Electrum drops the space between two characters of the scripts its wordlists are written in,
# where a space is a way of writing rather than a separator. These cover its own wordlists:
# hiragana, katakana and the ideographs of the Chinese and Japanese ones
CJK_RANGES = [(0x3040, 0x30ff), (0x3400, 0x4dbf), (0x4e00, 0x9fff), (0xf900, 0xfaff)]

# An extended key carries its key data last: a private one marks it with a leading zero, and a
# public one is the point itself, which is what the curve is asked about rather than the marker
EXTENDED_KEY_LENGTH_IN_BYTES = 78
KEY_DATA_STARTS_AT = 45
PRIVATE_KEY_MARKER = 0x00

# A rate outside these is refused whether a server quoted it or it was given by hand, and the fee
# itself may not take more than this share of the funds found. A server picks the rate, so without
# a ceiling it also picks how much of the recovery is left over
MIN_FEE_RATE = 1
MAX_FEE_RATE = 1_000
MAX_FEE_SHARE_OF_BALANCE = 0.10


def main():
    parser = argparse.ArgumentParser(
        description='Find and sweep the funds of a mnemonic or bitcoin key, across the derivation paths and address '
                    'formats the wallets known here are used with.'
    )

    parser.add_argument('key', nargs='?', default=None,
                        help='key to search, and to sweep when it is private: mnemonic, xpriv '
                             'or xpub, the root one or an account (asked for out of sight if '
                             'left off)')
    passphrase_source = parser.add_mutually_exclusive_group()
    passphrase_source.add_argument('--passphrase', metavar='<pass>', default='',
                                   help='optional secret phrase necessary to decode the mnemonic')
    passphrase_source.add_argument('--ask-passphrase', default=False, action='store_true',
                                   help='ask for the passphrase out of sight instead of reading it here')
    parser.add_argument('--allow-invalid-checksum', default=False, action='store_true',
                        help='derive from a mnemonic whose BIP39 checksum does not match')
    parser.add_argument('--electrum', default=False, action='store_true',
                        help='read the phrase as Electrum\'s when it reads as BIP39 as well')
    parser.add_argument('--show-bip85-phrase', default=False, action='store_true',
                        help='print what opens each BIP85 wallet found, which is also what '
                             'empties it and what stays in your scrollback')
    parser.add_argument('--show-multisig-keys', default=False, action='store_true',
                        help='print the multisig keys a private root holds, under BIP48 or '
                             'under Electrum\'s own convention, which reveal the addresses of '
                             'those branches to whoever reads them')

    sweep_tx = parser.add_argument_group('sweep transaction')

    sweep_tx.add_argument('--address', metavar='<address>',
                          help='craft a transaction sending all funds to this address')
    sweep_tx.add_argument('--broadcast', default=False, action='store_true',
                          help='if present broadcast the transaction to the network')
    sweep_tx.add_argument('--fee-rate', metavar='<rate>', type=int,
                          help='fee rate to use in sat/vbyte (default: next block fee)')
    sweep_tx.add_argument('--allow-high-fee', default=False, action='store_true',
                          help=f'allow a fee above {int(100 * MAX_FEE_SHARE_OF_BALANCE)}%% of the funds found')
    sweep_tx.add_argument('--yes', default=False, action='store_true',
                          help='broadcast without asking for confirmation')

    scanning = parser.add_argument_group('scanning parameters')

    scanning.add_argument('--address-gap', metavar='<num>', default=20, type=int,
                          help='max empty addresses gap to explore (default: 20)')
    scanning.add_argument('--bip85-indices', metavar='<num>', default=None, type=int,
                          help='how many BIP85 child wallets of this seed to look under. '
                               'Left off, three are looked under when nothing else turns '
                               'up, and none when it does; 0 looks under none at all')
    scanning.add_argument('--account-gap', metavar='<num>', default=0, type=int,
                          help='max empty account levels gap to explore (default: 0)')

    electrum = parser.add_argument_group('electrum server')

    electrum.add_argument('--host', metavar='<host>',
                          help='hostname of the electrum server to use')
    electrum.add_argument('--port', metavar='<port>', type=int,
                          help='port number of the electrum server to use')
    electrum.add_argument('--protocol', choices='ts', default='s',
                          help='electrum connection protocol: t=TCP, s=SSL (default: s)')
    electrum.add_argument('--no-batching', default=False, action='store_true',
                          help='disable request batching')
    electrum.add_argument('--insecure', default=False, action='store_true',
                          help='connect without verifying the server certificate, and allow plain TCP')

    args = parser.parse_args()

    if args.protocol == 't' and not args.insecure:
        parser.error('plain TCP puts every address this scans on the wire in the clear; '
                     'pass --insecure if that is what you want')

    if args.address is not None and scripts.build_output_script_from_address(args.address) is None:
        parser.error('the destination address is invalid or its format isn\'t recognized')

    key = _read_key(args.key)
    passphrase = _read_passphrase(args.passphrase, args.ask_passphrase)

    if args.bip85_indices is not None and args.bip85_indices < 0:
        parser.error('--bip85-indices counts wallets to look under, so it cannot be negative')

    # The version travels with the key rather than being worked out again here: the version
    # is an HMAC of the text, which any string has, and about one in two hundred and fifty
    # six lands on a prefix by chance. Only the parsing knows the input was read as a phrase
    master_key, electrum_version = parse_key(key, passphrase, args.allow_invalid_checksum, args.electrum)

    # Asked for by name, so it is said now rather than after a scan that could not have
    # looked. Left off, this is never reached: the search simply does not happen
    if args.bip85_indices and not _bip85_can_be_looked_under(master_key):
        parser.error('BIP85 hangs off a private root: every level of its path is hardened, '
                     'and the path is counted from the root, so neither a public key nor '
                     'the key of an account can reach it')

    if args.host is not None:
        port = (args.protocol + str(args.port)) if args.port else args.protocol
        server = ServerInfo(args.host, hostname=args.host, ports=port)
    else:
        server = random.choice(_read_servers())
        server = ServerInfo(server['host'], hostname=server['host'], ports=server['port'])

    asyncio.run(find_utxos(
        server,
        master_key,
        args.address_gap,
        args.account_gap,
        args.address,
        args.fee_rate,
        args.broadcast,
        not args.no_batching,
        args.allow_high_fee,
        args.yes,
        args.insecure,
        args.show_multisig_keys,
        electrum_version,
        args.bip85_indices,
        args.show_bip85_phrase
    ))


def _fee_rate_in_sat_per_vbyte(fee_rate_in_btc_per_kb: float) -> int:
    """
    Convert the fee rate an electrum server reports into satoshis per virtual byte.
    """
    # The rate arrives as a float, so it is read as the decimal it prints as: scaling the binary
    # value drops whole satoshis
    return int(Decimal(str(fee_rate_in_btc_per_kb)) * SATOSHIS_PER_BITCOIN / BYTES_PER_KILOBYTE)


def _confirmed() -> bool:
    """
    Ask before the sweep leaves the machine, since nothing can be undone afterwards.
    """
    return input('❓  Broadcast this transaction? [y/N] ').strip().lower() == 'y'


def _quoted_fee_rate(quoted_btc_per_kb: object) -> Optional[int]:
    """
    Read the fee rate a server quoted, or nothing at all if it is not a number one can pay.
    """
    if isinstance(quoted_btc_per_kb, bool) or not isinstance(quoted_btc_per_kb, (int, float)):
        return None

    try:
        if not math.isfinite(quoted_btc_per_kb):
            return None
    except OverflowError:
        # An integer too large to weigh against a float is not a fee rate either
        return None

    return _fee_rate_in_sat_per_vbyte(quoted_btc_per_kb)


def _read_servers() -> List[dict]:
    """
    Read the bundled list of electrum servers, wherever the tool was started from.
    """
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'servers.json')

    with open(path, 'r') as f:
        return json.load(f)


def _warn_about_the_command_line() -> None:
    """
    Say what passing a secret as an argument costs, since it outlives the recovery.
    """
    print('⚠️   Passing a secret as an argument leaves it in your shell history and in `ps`')
    print('    Leave it off the command line to be asked for it instead')


def _is_public_key(key: str) -> bool:
    """
    Whether this is an extended public key, the one input that is not worth hiding.
    """
    key_data = _key_data(key)

    return key_data is not None and _is_a_point(key_data)


def _read_key(given: Optional[str]) -> str:
    """
    Take the key from the command line if it is there, and ask for it out of sight if not.
    """
    if given is None:
        return getpass.getpass('Mnemonic, xpriv or xpub: ')

    if not _is_public_key(given):
        _warn_about_the_command_line()

    return given


def _read_passphrase(given: str, should_ask: bool) -> str:
    """
    Take the passphrase from the command line, or ask for it out of sight when asked to.
    """
    if should_ask:
        return getpass.getpass('Passphrase: ')

    if given:
        _warn_about_the_command_line()

    return given


def _is_a_cosigner_key(key: str) -> bool:
    """
    Whether an extended key is written as one that spends to a multisig output.
    """
    return _key_data(key) is not None and _version_of(key) in SLIP132_COSIGNER_VERSIONS


def _is_of_another_chain(key: str) -> bool:
    """
    Whether an extended key is written for a chain other than the one this searches.
    """
    return _key_data(key) is not None and _version_of(key) not in MAINNET_VERSIONS


def _placed(key: BIP32) -> BIP32:
    """
    Hand back a key this knows where to look under, and turn down one it does not.
    """
    # Under a root everything hangs below a hardened level, and under an account key the two
    # chains are right there. Anywhere else the addresses sit at a remove nothing here knows:
    # scanning anyway would hand a server hundreds of addresses of no one and end at a
    # negative answer that is simply wrong
    if key.depth in [ROOT_DEPTH, ACCOUNT_DEPTH]:
        return key

    raise ValueError(
        f'That key is {key.depth} levels down, and this can only place two: a root, at 0, and the '
        f'key of an account, at {ACCOUNT_DEPTH}, which is what a wallet exports. At any other '
        'depth the addresses hang at a remove this cannot guess, so there is nowhere here to '
        'look for them. Bring the seed phrase, the root key, or the account one.'
    )


def _as_mainnet(key: str) -> str:
    """
    Write a key spelled under a SLIP-132 prefix the way a mainnet key is spelled.
    """
    # SLIP-132 names the script type in the version bytes and changes nothing else, so the
    # key is the same key written another way. The library knows xprv and xpub and reads
    # anything else as another chain, so the four bytes are put back before it sees them
    if _version_of(key) not in SLIP132_MAINNET_VERSIONS:
        return key

    decoded = base58.b58decode_check(key)
    # Read off what the key carries rather than off the prefix: the two spellings of a
    # SLIP-132 pair differ in the prefix alone, which is the very thing being replaced
    version = XPRIV_VERSION if decoded[KEY_DATA_STARTS_AT] == PRIVATE_KEY_MARKER else XPUB_VERSION
    rewritten = version.to_bytes(VERSION_LENGTH_IN_BYTES, 'big') + decoded[VERSION_LENGTH_IN_BYTES:]

    return base58.b58encode_check(rewritten).decode()


def _version_of(key: str) -> int:
    """
    The version bytes an extended key is written under, which name its chain and script type.
    """
    return int.from_bytes(base58.b58decode_check(key)[:VERSION_LENGTH_IN_BYTES], 'big')


def _electrum_version_of(words: str) -> Optional[str]:
    """
    The version an Electrum phrase carries, or nothing if these words are not one of its own.
    """
    version = hmac.new(ELECTRUM_VERSION_KEY, _electrum_text(words).encode(), hashlib.sha512).hexdigest()

    for known in [ELECTRUM_STANDARD_VERSION, ELECTRUM_SEGWIT_VERSION] + ELECTRUM_TWO_FACTOR_VERSIONS:
        if not version.startswith(known):
            continue

        if known == ELECTRUM_COUNTED_TWO_FACTOR_VERSION and not _is_a_two_factor_length(words):
            return None

        return known

    return None


def _is_a_two_factor_length(words: str) -> bool:
    """
    Whether a phrase is as long as the two-factor wallet Electrum counts the words of.
    """
    counted = len(words.split())

    return counted == ELECTRUM_TWO_FACTOR_SHORT_LENGTH or counted >= ELECTRUM_TWO_FACTOR_LONG_LENGTH


def _electrum_seed(words: str, passphrase: str) -> bytes:
    """
    Stretch an Electrum phrase into a seed, which is BIP39's way over a salt of its own.
    """
    return hashlib.pbkdf2_hmac('sha512', _electrum_text(words).encode(),
                               ELECTRUM_SALT + _electrum_text(passphrase).encode(), PBKDF2_ROUNDS)


def _electrum_text(words: str) -> str:
    """
    Write a phrase the single way Electrum reads it before doing anything with the words.
    """
    written = unicodedata.normalize('NFKD', words).lower()
    written = ''.join(letter for letter in written if not unicodedata.combining(letter))
    written = ' '.join(written.split())

    return ''.join(letter for at, letter in enumerate(written)
                   if not (letter == ' ' and _is_cjk(written[at - 1]) and _is_cjk(written[at + 1])))


def _is_cjk(letter: str) -> bool:
    """
    Whether a character is written in one of the scripts that needs no space between words.
    """
    return any(first <= ord(letter) <= last for first, last in CJK_RANGES)


def _is_a_mnemonic(words: str) -> bool:
    """
    Whether a phrase is written in some BIP39 wordlist, whichever of them it turns out to be.
    """
    return any(_is_written_in(words, language) for language in Mnemonic.list_languages())


def _is_written_in(words: str, language: str) -> bool:
    """
    Whether every word of a phrase belongs to the wordlist of a given language.
    """
    wordlist = set(_wordlist_of(language))
    written = Mnemonic.normalize_string(words).split()

    return len(written) > 0 and all(word in wordlist for word in written)


def _wordlist_of(language: str) -> List[str]:
    """
    The wordlist of a language, written the way the words of a phrase arrive.
    """
    # The Turkish and Russian lists are not printed in the form a phrase comes in, and the
    # library looks its own words up as printed, so it cannot check a phrase in either of them
    return [Mnemonic.normalize_string(word) for word in Mnemonic(language).wordlist]


def _checksum_matches(words: str) -> bool:
    """
    Whether these words carry a valid BIP39 checksum in any of the wordlists.
    """
    # Wordlists share words, so a phrase can be written in more than one of them at once, and
    # the checksum is what settles which one it was really written in
    return any(Mnemonic(language, wordlist=_wordlist_of(language)).check(words)
               for language in Mnemonic.list_languages())


def _key_data(key: str) -> Optional[bytes]:
    """
    The key data an extended key carries, or nothing if the string is no extended key at all.
    """
    try:
        decoded = base58.b58decode_check(key)
    except Exception:
        return None

    if len(decoded) != EXTENDED_KEY_LENGTH_IN_BYTES:
        return None

    return decoded[KEY_DATA_STARTS_AT:]


def _is_a_point(key_data: bytes) -> bool:
    """
    Whether key data stands for a point on the curve, which the marker it begins with can't say.
    """
    try:
        coincurve.PublicKey(key_data)
        return True
    except Exception:
        return False


def _is_private_key(key: str) -> bool:
    """
    Whether this is an extended private key, told apart by the marker its key data begins with.
    """
    key_data = _key_data(key)

    return key_data is not None and key_data[0] == PRIVATE_KEY_MARKER


def parse_key(key: str, passphrase: str, allow_invalid_checksum: bool = False,
              prefer_electrum: bool = False) -> Tuple[BIP32, Optional[str]]:
    """
    Try to parse an extended key, whether it is in xpub, xpriv or mnemonic format.

    Hands back the key and, when the input was read as an Electrum phrase, the version it
    carries, which is what says where a wallet grown from it would keep a multisig.
    """
    if _is_of_another_chain(key):
        raise ValueError(
            'That key belongs to another chain: its prefix is not one of the ways a mainnet key '
            'is written. This looks up mainnet addresses on mainnet servers, so it has nowhere '
            'to search for it.'
        )

    if _is_a_cosigner_key(key):
        raise ValueError(
            'That is the key of a multisig cosigner: its prefix is one of the four SLIP-132 '
            'spellings that say the output is a multisig one. The addresses of that wallet are '
            'built from the keys of every cosigner and the number of them that must sign, so '
            'this one alone derives none of them and there is nothing here to search for. '
            'Recovering it takes a wallet that can put the cosigners back together.'
        )

    if _is_private_key(key):
        try:
            private_key = BIP32.from_xpriv(_as_mainnet(key))
        except Exception:
            pass
        else:
            # Placed before the success is announced: a key this cannot look under is not one
            # it read to any purpose, and saying so first and turning it down after reads as
            # though the refusal came from somewhere else
            placed = _placed(private_key)
            print('🔑  Read private key successfully')
            return placed, None

    if _is_public_key(key):
        try:
            public_key = BIP32.from_xpub(_as_mainnet(key))
        except Exception:
            pass
        else:
            # Placed before the success is announced: a key this cannot look under is not one
            # it read to any purpose, and saying so first and turning it down after reads as
            # though the refusal came from somewhere else
            placed = _placed(public_key)
            print('🔑  Read public key successfully')
            return placed, None

    electrum_version = _electrum_version_of(key)

    # The version Electrum reads out of a phrase is not a checksum of belonging: about one BIP39
    # phrase in two hundred lands on one of its prefixes by chance. When a phrase reads as both,
    # it is taken as BIP39, which is the wallet far more of them come from, and it is said out
    # loud rather than decided quietly
    if electrum_version is not None and not prefer_electrum and _checksum_matches(key):
        print('⚠️  These words read as an Electrum seed phrase as well, which is another wallet')
        print('    entirely. Taking them as BIP39; pass `--electrum` to take them as Electrum\'s')
        electrum_version = None

    if electrum_version in ELECTRUM_TWO_FACTOR_VERSIONS:
        raise ValueError(
            'That is an Electrum two-factor seed phrase. The words do hold the funds: they carry '
            'two of the three keys of that wallet, which is enough to spend from it. What they '
            'need is a two-of-three multisig, which this tool cannot build. Electrum restores it '
            'from these same words.'
        )

    if electrum_version is not None:
        private_key = BIP32.from_seed(_electrum_seed(key, passphrase))
        print('🔑  Read Electrum seed phrase successfully')
        return private_key, electrum_version

    if _is_a_mnemonic(key):
        # A phrase arrives with whatever spacing the document it was copied out of had, and the
        # seed is built out of the text itself, so it is checked and derived in one same form
        words = ' '.join(Mnemonic.normalize_string(key).split())

        if not allow_invalid_checksum and not _checksum_matches(words):
            raise ValueError(
                'Those words don\'t add up: the BIP39 checksum doesn\'t match, which usually means a '
                'word was mistyped or two were swapped. An Electrum seed phrase uses the same words '
                'but is not BIP39, and lands here too. Pass `--allow-invalid-checksum` to derive from '
                'those words anyway.'
            )

        seed = Mnemonic.to_seed(words, passphrase=passphrase)
        private_key = BIP32.from_seed(seed)
        print('🔑  Read mnemonic successfully')
        return private_key, None

    raise ValueError('The key is invalid or the format isn\'t recognized. Make sure it\'s a mnemonic, xpriv or xpub.')


def _report_what_a_public_key_reaches(master_key: BIP32) -> None:
    """
    Say which of the paths a public key can walk, which depends on where the key sits.
    """
    print('🔍  A public key reaches only the two chains right under it, and nothing below a')
    print('    hardened level. Nothing can be swept without the private key either')

    if master_key.depth == ACCOUNT_DEPTH:
        return

    # A root is the only other key that gets here, and under one those two paths are an
    # Electrum standard wallet: a BIP44, BIP49 or BIP84 wallet keeps its addresses below the
    # hardened level of an account, out of reach of any public key
    print('    This key is a root, so that is an Electrum standard wallet and nothing else')
    print('    A BIP44, BIP49 or BIP84 wallet keeps its addresses under an account: for those,')
    print('    bring the account xpub, which is the one a wallet exports')


def _multisig_keys_of(electrum_version: Optional[str]) -> Tuple[str, List[Tuple[List[int], str, str]]]:
    """
    Where a wallet grown from this seed keeps a multisig, and which keys hang there.
    """
    # Which standard applies is decided by the seed, not by the key: a root derived from an
    # Electrum phrase and one derived from a BIP39 phrase look the same and are asked for at
    # different paths, so handing over the BIP48 ones either way rebuilds somebody else's wallet
    if electrum_version == ELECTRUM_STANDARD_VERSION:
        return 'Electrum puts a multisig of these words under', [([], 'm', 'P2SH')]

    if electrum_version == ELECTRUM_SEGWIT_VERSION:
        return ('Electrum puts a multisig of these words under',
                [([ELECTRUM_MULTISIG_BRANCH + HARDENED_INDEX], f"m/{ELECTRUM_MULTISIG_BRANCH}'", 'P2WSH')])

    return (f'BIP48 puts account {MULTISIG_ACCOUNT} of such a wallet under',
            [([BIP48_PURPOSE + HARDENED_INDEX, MAINNET_COIN_TYPE + HARDENED_INDEX,
               MULTISIG_ACCOUNT + HARDENED_INDEX, branch + HARDENED_INDEX],
              f"m/{BIP48_PURPOSE}'/{MAINNET_COIN_TYPE}'/{MULTISIG_ACCOUNT}'/{branch}'", script_type)
             for branch, script_type in MULTISIG_BRANCHES])


def _report_multisig_keys(master_key: BIP32, should_show_keys: bool,
                          electrum_version: Optional[str] = None) -> None:
    """
    Say what a multisig of this seed would take, and hand over its keys if they were asked for.
    """
    where, branches = _multisig_keys_of(electrum_version)

    print()
    print('🔑  A multisig wallet cannot be searched for from one seed: its addresses are built')
    print('    from every cosigner at once, so this scan says nothing either way about one')

    # What this key can give comes before what was asked of it: offering a flag that would
    # answer with an excuse is worse than saying the excuse now
    if master_key.privkey is None:
        print('    Its keys hang off levels a public key cannot derive: that takes the seed')
        print('    phrase or the root xpriv')
        return

    if master_key.depth != ROOT_DEPTH:
        print(f'    Those levels are counted from the root, and this key is {master_key.depth} under one,')
        print('    so its keys take the seed phrase or the root xpriv')
        return

    if not should_show_keys:
        print(f'    Pass `--show-multisig-keys` for the keys {where}')
        return

    print('    What is missing is the other cosigners\' keys and how many must sign, along')
    print(f'    with these, which {where}:')

    for path, spelled, script_type in branches:
        written = master_key.get_xpub_from_path(path) if path else master_key.get_xpub()

        print(f'    {spelled}  {script_type:{SCRIPT_TYPE_COLUMN}}  {written}')


# How many wallets a seed is looked under when nobody said, which happens only once a scan
# of the seed itself has come up empty
BIP85_INDICES_WHEN_NOBODY_SAID = 3


def _bip85_can_be_looked_under(master_key: BIP32) -> bool:
    """
    Whether BIP85 is even reachable from this key, which takes a private root.
    """
    # Every level of a BIP85 path is hardened, so a public key derives none of them. And the
    # path is counted from the root: an account key is private and still cannot walk it
    return master_key.privkey is not None and master_key.depth == ROOT_DEPTH


def _report_no_bip85_was_looked_under(master_key: BIP32) -> None:
    """
    Say that another wallet may hide under this seed and that nothing looked for it.
    """
    print()
    print('🌱  A seed can be the parent of other seeds under BIP85, and those are wallets of')

    if not _bip85_can_be_looked_under(master_key):
        print('    their own. Looking under them takes the seed phrase or the root xpriv, since')
        print('    every level of that path is hardened and counted from the root')
        return

    print('    their own, with their own funds. Pass `--bip85-indices` to look under them')


def _report_a_child_that_was_used(index: int, form: str, found: List[Script], balance: int) -> None:
    """
    Name a wallet hiding under this seed, without handing over what spends it.
    """
    # The path and the address are what make it recognisable, and neither of them spends
    # anything. The phrase does, so it is kept back until somebody asks for it by name
    print(f'🌱  Index {index}, {form}: a wallet under this seed that has been used')
    print(f'    {found[0].full_path().path}  {scripts.address_of(found[0].program)}')

    # The sum below is over every address that had a history, and the one printed above is
    # the first of them. Writing an amount under a single address that may hold none of it
    # would say the money is somewhere it is not
    if len(found) > 1:
        print(f'    and at {len(found) - 1} more of the addresses looked at')

    # What was asked about is a handful of addresses, not the wallet, so this is a floor
    # and never a total. Calling it the balance would say a wallet is empty when the money
    # is at a path this did not look at, which is the sentence that ends a search
    if balance:
        print(f'    At least {balance} sats at the addresses looked at')
    else:
        print('    Nothing at the addresses looked at, which is not the same as nothing in it')


def _report_what_a_bip85_search_covered(indices: int) -> None:
    """
    Say what was looked under, since a search that says nothing about its own reach reads
    as though it had looked everywhere.
    """
    print(f'    Looked under {indices} {"index" if indices == 1 else "indices"}, 0 to '
          f'{indices - 1}, in English, at twelve, eighteen and twenty four words, plus the')
    print('    extended key and the seed Bitcoin Core takes. Not other languages, not other')
    print('    word counts, and not a passphrase on the child. Of each of those wallets only')
    print('    the first address of every path was asked about, so one used further along is')
    print('    not ruled out, and neither is an index past the ones looked under')


def _hand_over_what_spends_a_child(master_key: BIP32, index: int, form: str,
                                   root: BIP32) -> None:
    """
    Print what opens one of those wallets, which was asked for by name.
    """
    print('    ⚠️   What follows spends those funds, and stays in your scrollback and in')
    print('        whatever keeps a log of this terminal')

    if form in bip85.WORD_FORM_NAMES:
        print(f'        {bip85.mnemonic_child(master_key, bip85.WORD_FORM_NAMES[form], index)}')
        return

    if form == 'wif':
        print(f'        {bip85.wif_child(master_key, index)}   (Bitcoin Core hdseed)')

    print(f'        {root.get_xpriv()}')


async def _look_under_bip85(client: StratumClient, master_key: BIP32, indices: int,
                            should_batch: bool, show_phrase: bool) -> bool:
    """
    Look under the wallets this seed hides, and name the ones a server has ever seen.
    """
    children = [(index, form, root)
                for index in range(indices)
                for form, root in bip85.children(master_key, index)]

    used = await scanner.which_children_were_used(
        client, [(f'{index}:{form}', root) for index, form, root in children], should_batch)

    if not used:
        return False

    balances = await scanner.balances_at(client, [found for _, found in used])
    roots = {f'{index}:{form}': root for index, form, root in children}

    for (name, found), balance in zip(used, balances):
        index, form = name.split(':')
        print()
        _report_a_child_that_was_used(int(index), form, found, balance)

        if show_phrase:
            _hand_over_what_spends_a_child(master_key, int(index), form, roots[name])

    print()

    if not show_phrase:
        print('    Each of those is a wallet of its own. Pass `--show-bip85-phrase` to be')
        print('    handed what opens it, which is also what empties it')

    return True


async def find_utxos(
        server: ServerInfo,
        master_key: BIP32,
        address_gap: int,
        account_gap: int,
        address: Optional[str],
        fee_rate: Optional[int],
        should_broadcast: bool,
        should_batch: bool,
        allow_high_fee: bool = False,
        assume_yes: bool = False,
        insecure: bool = False,
        show_multisig_keys: bool = False,
        electrum_version: Optional[str] = None,
        bip85_indices: Optional[int] = None,
        show_bip85_phrase: bool = False
):
    """
    Connect to an electrum server and find every UTXO a key reaches, spendable or not.
    """
    if master_key.privkey is None:
        _report_what_a_public_key_reaches(master_key)

    if not insecure and server.protocols != {'s'}:
        print('⛔️  That server would be reached over plain TCP, putting every address this looks up')
        print('    on the wire in the clear. Pass `--insecure` if that is what you want')
        return

    print('⏳  Connecting to electrum server, this might take a while')

    client = StratumClient(my_proto_version=ELECTRUM_PROTOCOL_VERSIONS)
    await client.connect(server, disable_cert_verify=insecure)

    print('🌍  Connected to electrum server successfully')

    utxos = await scanner.scan_master_key(client, master_key, address_gap, account_gap, should_batch)

    # How far to look under this seed, when nobody said. A scan that found nothing is the
    # moment to look; one that found something is not worth the wait unless it was asked for
    asked_for_bip85 = bip85_indices is not None
    looking_under = bip85_indices if asked_for_bip85 else (
        BIP85_INDICES_WHEN_NOBODY_SAID if len(utxos) == 0 else 0)

    if looking_under and not _bip85_can_be_looked_under(master_key):
        looking_under = 0

    named_a_child = False

    # Before the sad face and before the sweep alike: with `--yes` nobody reads what comes
    # after the transaction, and a sweep of the seed is not a sweep of what hides under it
    if looking_under:
        named_a_child = await _look_under_bip85(client, master_key, looking_under,
                                                should_batch, show_bip85_phrase)

    if len(utxos) == 0:
        if not named_a_child:
            print('😔  Didn\'t find any unspent outputs')

        if looking_under:
            _report_what_a_bip85_search_covered(looking_under)
        else:
            _report_no_bip85_was_looked_under(master_key)

        _report_multisig_keys(master_key, show_multisig_keys, electrum_version)
        client.close()
        return

    # Everything BIP85 has to say goes before the first number about this key's own money,
    # since with `--yes` the hex and the broadcast follow that number without a pause
    if looking_under:
        _report_what_a_bip85_search_covered(looking_under)
    else:
        _report_no_bip85_was_looked_under(master_key)

    balance = sum([utxo.amount_in_sat for utxo in utxos])
    print()
    print(f'💸  Total spendable balance found in the key that was read: {balance} sats')

    _report_multisig_keys(master_key, show_multisig_keys, electrum_version)

    if master_key.privkey is None:
        print('✍️  Re-run with a private key to create a sweep transaction')
        client.close()
        return

    if address is None:
        print('ℹ️   Re-run with `--address` to create a sweep transaction')
        client.close()
        return

    if fee_rate is None:
        quoted_btc_per_kb = await client.RPC('blockchain.estimatefee', 1)

        if quoted_btc_per_kb == -1:
            print('🔁  Couldn\'t fetch fee rates, try again with manual fee rates using `--fee-rate`')
            client.close()
            return

        fee_rate = _quoted_fee_rate(quoted_btc_per_kb)

        if fee_rate is None:
            print(f'⛔️  The server quoted {quoted_btc_per_kb!r}, which is not a fee rate that can be paid')
            client.close()
            return

        print(f'🚌  Fetched next-block fee rate of {fee_rate} sat/vbyte')

    if not MIN_FEE_RATE <= fee_rate <= MAX_FEE_RATE:
        print(f'⛔️  A fee rate of {fee_rate} sat/vbyte is outside the range this tool will pay')
        print(f'    Pick one between {MIN_FEE_RATE} and {MAX_FEE_RATE} with `--fee-rate`')
        client.close()
        return

    tx_without_fee = transactions.Transaction(master_key, utxos, address, balance)
    fee = tx_without_fee.virtual_size() * fee_rate

    if fee > balance * MAX_FEE_SHARE_OF_BALANCE and not allow_high_fee:
        share = 100 * fee / balance
        print(f'⛔️  A fee of {fee} sats is {share:.1f}% of the {balance} sats found')
        print('    Re-run with `--allow-high-fee` if that is really what you want')
        client.close()
        return

    tx = transactions.Transaction(master_key, utxos, address, balance - fee)
    bin_tx = tx.to_bytes()
    # Signing the real transaction can land on a signature a byte or two off the provisional one,
    # so the rate it ends up paying is close to the one asked for rather than exactly it
    paid_rate = fee / tx.virtual_size()

    print('👇  This transaction sweeps all funds of the key that was read, to the address given')
    print()
    print(f'    To:    {address}')
    print(f'    Sends: {balance - fee} sats')
    print(f'    Fee:   {fee} sats, at {paid_rate:.2f} sat/vbyte, '
          f'{100 * fee / balance:.1f}% of the {balance} sats found')
    print()
    print(bin_tx.hex())
    print()

    if not should_broadcast:
        print('📋  Copy this transaction and broadcast it manually to the network, or re-run with `--broadcast`')
        client.close()
        return

    if not assume_yes and not _confirmed():
        print('🚫  Left alone, nothing was broadcast')
        client.close()
        return

    try:
        print('📣  Broadcasting transaction to the network')
        txid = await client.RPC('blockchain.transaction.broadcast', bin_tx.hex())
        print(f'✅  Transaction {txid} successfully broadcasted')
    except connectrum.exc.ElectrumErrorResponse as err:
        print(f'⛔️  Transaction broadcasting failed: {err}')

    client.close()


if __name__ == '__main__':
    main()
