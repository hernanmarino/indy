#!/usr/bin/env python3
import hashlib
from enum import Enum, auto
from typing import Optional, List, Tuple

import base58
import bech32

OP_0 = 0x00
OP_1 = 0x51
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac

P2PKH_ADDRESS_HEADER = 0x00
P2SH_ADDRESS_HEADER = 0x05
BECH32_HRP = 'bc'
BECH32_SEPARATOR = '1'

# The two checksums tell the address flavors apart: BIP350 kept bech32 for the witness version 0
# addresses already in the wild, and gave every later version bech32m, so that an address for a
# version an old wallet doesn't know about fails its checksum instead of being paid the wrong way
BECH32_CHECKSUM = 1
BECH32M_CHECKSUM = 0x2bc8_30a3

CHECKSUM_LENGTH_IN_CHARS = 6
MAX_WITNESS_VERSION = 16
MIN_WITNESS_PROGRAM_LENGTH_IN_BYTES = 2
MAX_WITNESS_PROGRAM_LENGTH_IN_BYTES = 40
P2WPKH_PROGRAM_LENGTH_IN_BYTES = 20
P2WSH_PROGRAM_LENGTH_IN_BYTES = 32

# The range of characters a bech32 string is made of
MIN_BECH32_CHAR = 33
MAX_BECH32_CHAR = 126

sha256 = lambda bytes: hashlib.sha256(bytes).digest()
ripemd160 = lambda bytes: hashlib.new('ripemd160', bytes).digest()
hash160 = lambda bytes: ripemd160(sha256(bytes))


class ScriptType(Enum):
    """
    Single-key output script type.
    """
    LEGACY = auto()  # P2PKH
    COMPAT = auto()  # P2SH of P2WPKH
    SEGWIT = auto()  # P2WPKH

    def build_output_script(self, pubkey: bytes) -> bytes:
        """
        Compute the output script for a given public key.
        """
        if self is ScriptType.LEGACY:
            return _build_p2pkh_output_script(hash160(pubkey))

        if self is ScriptType.COMPAT:
            script = _build_segwit_output_script(0, hash160(pubkey))
            return _build_p2sh_output_script(hash160(script))

        if self is ScriptType.SEGWIT:
            return _build_segwit_output_script(0, hash160(pubkey))

        raise ValueError('Unrecognized address type')

    def build_input_script(self, pubkey: bytes, signature: bytes) -> bytes:
        """
        Compute the input script for a given public key and signature.
        """
        if self is ScriptType.LEGACY:
            return _build_p2pkh_input_script(pubkey, signature)

        if self is ScriptType.COMPAT:
            script = _build_segwit_output_script(0, hash160(pubkey))
            return _build_p2sh_input_script(script)

        if self is ScriptType.SEGWIT:
            return bytes()

        raise ValueError('Unrecognized address type')

    def build_witness(self, pubkey: bytes, signature: bytes) -> List[bytes]:
        """
        Compute the witness for a given public key and signature.
        """
        if self is ScriptType.LEGACY:
            return []

        if self in [ScriptType.COMPAT, ScriptType.SEGWIT]:
            return [signature, pubkey]

        raise ValueError('Unrecognized address type')


def build_output_script_from_address(address: str) -> Optional[bytes]:
    """
    Compute the output script for a given address.
    """
    # Try to decode a base58 address
    try:
        decoded = base58.b58decode_check(address)
        version = decoded[0]
        hash = decoded[1:]

        if version == P2PKH_ADDRESS_HEADER:
            return _build_p2pkh_output_script(hash)

        if version == P2SH_ADDRESS_HEADER:
            return _build_p2sh_output_script(hash)

    except ValueError:
        pass

    # Try to decode a segwit address
    decoded = _decode_segwit_address(address)

    if decoded is not None:
        version, program = decoded
        return _build_segwit_output_script(version, program)

    return None


def _decode_segwit_address(address: str) -> Optional[Tuple[int, bytes]]:
    """
    Read the witness version and program out of a segwit address, or nothing if it isn't one.
    """
    # Case folding can turn a character from outside the range into one inside it, the Kelvin sign
    # into a plain k among them, so the range is what the address is held to first
    if any(not MIN_BECH32_CHAR <= ord(character) <= MAX_BECH32_CHAR for character in address):
        return None

    if address.lower() != address and address.upper() != address:
        return None

    address = address.lower()

    prefix = BECH32_HRP + BECH32_SEPARATOR

    if not address.startswith(prefix):
        return None

    characters = address[len(prefix):]

    if len(characters) <= CHECKSUM_LENGTH_IN_CHARS:
        return None

    if any(character not in bech32.CHARSET for character in characters):
        return None

    values = [bech32.CHARSET.find(character) for character in characters]
    version = values[0]

    if version > MAX_WITNESS_VERSION:
        return None

    checksum = BECH32_CHECKSUM if version == 0 else BECH32M_CHECKSUM

    if bech32.bech32_polymod(bech32.bech32_hrp_expand(BECH32_HRP) + values) != checksum:
        return None

    program = bech32.convertbits(values[1:-CHECKSUM_LENGTH_IN_CHARS], 5, 8, False)

    if program is None or not _witness_program_length_is_valid(version, len(program)):
        return None

    return version, bytes(program)


def _witness_program_length_is_valid(version: int, length_in_bytes: int) -> bool:
    """
    Check a witness program against the length segwit allows it, which BIP141 narrows for version 0.
    """
    if not MIN_WITNESS_PROGRAM_LENGTH_IN_BYTES <= length_in_bytes <= MAX_WITNESS_PROGRAM_LENGTH_IN_BYTES:
        return False

    if version == 0:
        return length_in_bytes in [P2WPKH_PROGRAM_LENGTH_IN_BYTES, P2WSH_PROGRAM_LENGTH_IN_BYTES]

    return True


def _build_p2pkh_output_script(pubkey_hash: bytes) -> bytes:
    script = bytearray()

    script.append(OP_DUP)
    script.append(OP_HASH160)
    script.append(len(pubkey_hash))
    script.extend(pubkey_hash)
    script.append(OP_EQUALVERIFY)
    script.append(OP_CHECKSIG)

    return bytes(script)


def _build_p2sh_output_script(script_hash: bytes) -> bytes:
    script = bytearray()

    script.append(OP_HASH160)
    script.append(len(script_hash))
    script.extend(script_hash)
    script.append(OP_EQUAL)

    return bytes(script)


def _build_segwit_output_script(version: int, program: bytes) -> bytes:
    script = bytearray()

    script.append(OP_0 if version == 0 else OP_1 + version - 1)
    script.append(len(program))
    script.extend(program)

    return bytes(script)


def _build_p2pkh_input_script(pubkey: bytes, signature: bytes) -> bytes:
    script = bytearray()

    script.append(len(signature))
    script.extend(signature)
    script.append(len(pubkey))
    script.extend(pubkey)

    return bytes(script)


def _build_p2sh_input_script(*args: bytes) -> bytes:
    script = bytearray()

    for arg in args:
        script.append(len(arg))
        script.extend(arg)

    return bytes(script)
