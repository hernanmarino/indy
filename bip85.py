#!/usr/bin/env python3
import hashlib
import hmac
from typing import List, Tuple

import base58
from bip32 import BIP32, HARDENED_INDEX
from mnemonic import Mnemonic

# What BIP85 counts its own derivations from, and the tag it stretches the key under. The
# tag is what keeps this entropy from being anything else derived from the same key
PURPOSE = 83696968
ENTROPY_KEY = b'bip-entropy-from-k'

# The applications that hand back a wallet this can look for. The rest of them — passwords,
# dice, RSA, Nostr — are not wallets, so nothing here would know where to look
MNEMONIC_APP = 39
XPRV_APP = 32
WIF_APP = 2
ENGLISH = 0

# How many bytes of the entropy each word count is spelled out of
WORD_COUNTS = {12: 16, 18: 24, 24: 32}

# What each form is asked for and reported under, and what a word form means
WORD_FORM_NAMES = {f'{words}w': words for words in WORD_COUNTS}

# Where the chain code ends and the private key begins in an xprv child, which is the other
# way round from how BIP32 lays a key out
CHAINCODE_LENGTH_IN_BYTES = 32
SECRET_LENGTH_IN_BYTES = 32

# What a compressed private key is written as
WIF_MAINNET_PREFIX = 0x80
WIF_COMPRESSED_SUFFIX = 0x01

CURVE_ORDER = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe_baae_dce6_af48_a03b_bfd2_5e8c_d036_4141


# Its own class, and not a bare ValueError, because BIP32 raises one of those for the very
# same key: catching ValueError would turn any failure in the derivation into 'that form
# does not exist', and a form that quietly does not exist is a wallet nobody looks for
class UnusableChild(ValueError):
    """
    Raised for a child whose key the curve has no point for, which is passed over.
    """


def hardened(path: List[int]) -> List[int]:
    """
    Write a path the way BIP85 derives it, which is hardened the whole way down.
    """
    return [level + HARDENED_INDEX for level in path]


def entropy(root: BIP32, path: List[int]) -> bytes:
    """
    Stretch the key a BIP85 path derives into the entropy every application is cut out of.
    """
    return hmac.new(ENTROPY_KEY, root.get_privkey_from_path(hardened([PURPOSE] + path)),
                    hashlib.sha512).digest()


def mnemonic_child(root: BIP32, words: int, index: int) -> str:
    """
    Spell out the BIP39 phrase a seed hides at one index, which is a wallet of its own.
    """
    cut = entropy(root, [MNEMONIC_APP, ENGLISH, words, index])[:WORD_COUNTS[words]]

    return Mnemonic('english').to_mnemonic(cut)


def child_root(root: BIP32, words: int, index: int) -> BIP32:
    """
    Derive the key of a phrase child, which comes from the words and not from the bytes.
    """
    # The entropy spells the words; the key is those words stretched the way BIP39 stretches
    # any phrase. Seeding from the entropy instead builds another wallet that looks correct
    # from every angle the published vectors can see
    return BIP32.from_seed(Mnemonic.to_seed(mnemonic_child(root, words, index)))


def xprv_child(root: BIP32, index: int) -> BIP32:
    """
    Derive the extended private key a seed hides at one index.
    """
    cut = entropy(root, [XPRV_APP, index])
    secret = cut[CHAINCODE_LENGTH_IN_BYTES:CHAINCODE_LENGTH_IN_BYTES + SECRET_LENGTH_IN_BYTES]

    _on_the_curve(secret)

    # A root, so depth, fingerprint and index are all nought: anything else is a key this
    # program would turn down for sitting somewhere it cannot look under
    return BIP32(chaincode=cut[:CHAINCODE_LENGTH_IN_BYTES], privkey=secret)


def wif_child(root: BIP32, index: int) -> str:
    """
    Write the key a seed hides at one index the way Core reads it as an hdseed.
    """
    secret = _hdseed(root, index)

    return base58.b58encode_check(bytes([WIF_MAINNET_PREFIX]) + secret
                                  + bytes([WIF_COMPRESSED_SUFFIX])).decode()


def hdseed_root(root: BIP32, index: int) -> BIP32:
    """
    Derive the wallet Bitcoin Core builds when it is handed that key as its hdseed.
    """
    return BIP32.from_seed(_hdseed(root, index))


def children(root: BIP32, index: int) -> List[Tuple[str, BIP32]]:
    """
    Derive every wallet one seed hides at one index, by the name each form is asked for.

    A form whose key the curve does not admit is passed over; the others of that index are
    not, since they are worked out from entropy of their own.
    """
    placed = []

    for form, words in WORD_FORM_NAMES.items():
        placed.append((form, child_root(root, words, index)))

    # These two are the ones a key can come out of unusable, and only they are passed over:
    # the word children above are cut from entropy of their own
    for form, derive in [('xprv', xprv_child), ('wif', hdseed_root)]:
        try:
            placed.append((form, derive(root, index)))
        except UnusableChild:
            continue

    return placed


def _hdseed(root: BIP32, index: int) -> bytes:
    """
    Cut out the key the WIF application hands over, before it is written as one.
    """
    secret = entropy(root, [WIF_APP, index])[:SECRET_LENGTH_IN_BYTES]

    _on_the_curve(secret)

    return secret


def _on_the_curve(secret: bytes) -> None:
    """
    Turn down a key the curve has no point for, which the standard says to pass over.
    """
    if not 0 < int.from_bytes(secret, 'big') < CURVE_ORDER:
        raise UnusableChild('That index yields a secret outside the curve order')
