#!/usr/bin/env python3
from __future__ import annotations

from typing import List, Tuple

import coincurve
from bip32 import BIP32

import scanner
import scripts

VERSION = 2
SEGWIT_MARKER = 0
SEGWIT_FLAG = 1
SEQUENCE = 0xffff_ffff
LOCKTIME = 0x0000_0000
SIGHASH_ALL = 0x01

# Taproot signs over a single sha256 under a tag, and says nothing about the hash type when
# it is the default one. The spend type is nought here: no annex, and the key path, not a script
SIGHASH_DEFAULT = 0x00
TAPSIGHASH_TAG = 'TapSighash'
TAPROOT_EPOCH = 0x00
TAPROOT_KEY_PATH_SPEND_TYPE = 0x00
CURVE_ORDER = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe_baae_dce6_af48_a03b_bfd2_5e8c_d036_4141
SCALAR_LENGTH_IN_BYTES = 32
ODD_Y_PREFIX = 0x03

NON_SEGWIT_DUST = 546


class Transaction:
    """
    Sweep transaction.
    """

    def __init__(self, master_key: BIP32, utxos: List[scanner.Utxo], address: str, amount_in_sat: int):
        """
        Craft and sign a transaction that spends all the UTXOs and sends the requested funds to a specific address.
        """
        output_script = scripts.build_output_script_from_address(address)
        if output_script is None:
            raise ValueError('The address is invalid or the format isn\'t recognized.')

        if amount_in_sat < NON_SEGWIT_DUST:
            raise ValueError('Not enough funds to create a sweep transaction.')

        self.outputs = [(amount_in_sat, output_script)]
        self.inputs = []

        # A taproot digest covers every input's amount and the script each one pays, so all of
        # them are worked out once, before any one input is signed
        pubkeys = [master_key.get_pubkey_from_path(utxo.path.to_list()) for utxo in utxos]
        spent = [(_outpoint_of(utxo), utxo.amount_in_sat,
                  utxo.script_type.build_output_script(pubkey), SEQUENCE)
                 for utxo, pubkey in zip(utxos, pubkeys)]

        for index in range(len(utxos)):
            utxo = utxos[index]
            pubkey = pubkeys[index]

            privkey = master_key.get_privkey_from_path(utxo.path.to_list())

            if utxo.script_type == scripts.ScriptType.TAPROOT:
                # Taproot signs a single sha256 under a tag, with Schnorr, over the key the
                # output really pays rather than the one the path derived
                hash = _taproot_sighash(index, spent, self.outputs)
                tweaked = coincurve.PrivateKey(_taproot_privkey(privkey, pubkey))

                # Nothing is appended: SIGHASH_DEFAULT is the hash type a 64 byte signature means
                signature = tweaked.sign_schnorr(hash)

                self.inputs.append((
                    utxo,
                    utxo.script_type.build_input_script(pubkey, signature),
                    utxo.script_type.build_witness(pubkey, signature)
                ))
                continue

            # Build the inputs for signing: they should all have empty scripts, save for the input that we are signing,
            # which should have the output script of a P2PKH output.
            script = scripts.ScriptType.LEGACY.build_output_script(pubkey)
            inputs = [(u, script if u == utxo else b'', []) for u in utxos]

            if utxo.script_type == scripts.ScriptType.LEGACY:
                # If this is a legacy input, then the transaction digest is just the wire format serialization.
                tx = _serialize_tx(inputs, self.outputs, include_witness=False)
            else:
                # If this is a segwit input (native or not), then the transaction digest is the one defined in BIP143.
                tx = _serialize_tx_for_segwit_signing(index, inputs, self.outputs)

            # To produce the final message digest we need to append the sig-hash type, and double sha256 the message.
            tx.extend(SIGHASH_ALL.to_bytes(4, 'little'))
            hash = scripts.sha256(scripts.sha256(bytes(tx)))

            signature = coincurve.PrivateKey(privkey).sign(hash, hasher=None)

            extended_signature = bytearray(signature)
            extended_signature.append(SIGHASH_ALL)
            extended_signature = bytes(extended_signature)

            self.inputs.append((
                utxo,
                utxo.script_type.build_input_script(pubkey, extended_signature),
                utxo.script_type.build_witness(pubkey, extended_signature)
            ))

    def virtual_size(self) -> int:
        """
        Compute the size of the transaction in virtual bytes.
        """
        witness_tx = _serialize_tx(self.inputs, self.outputs)
        non_witness_tx = _serialize_tx(self.inputs, self.outputs, include_witness=False)
        weight = 3 * len(non_witness_tx) + len(witness_tx)

        # BIP141 rounds the weight up to the next whole virtual byte
        return (weight + 3) // 4

    def to_bytes(self) -> bytes:
        """
        Serialize the transaction according to BIP144 for witness transactions, and according to the old serialization
        format for non-witness transactions.
        """
        return _serialize_tx(self.inputs, self.outputs)


def read_transaction(raw: bytes) -> Tuple[str, List[Tuple[int, bytes]]]:
    """
    Read a serialized transaction, returning the id it is known by and its outputs.
    """
    reader = _Reader(raw)

    version = reader.take(4)
    inputs, witness_flag = _read_inputs(reader)
    outputs = _read_outputs(reader)

    if witness_flag:
        for _ in inputs:
            for _ in range(reader.varint()):
                reader.take(reader.varint())

    locktime = reader.take(4)
    reader.done()

    # An id never covers the witness, so it is taken over the transaction without one
    without_witness = bytearray(version)
    without_witness.extend(_varint(len(inputs)))

    for outpoint, script, sequence in inputs:
        without_witness.extend(outpoint)
        without_witness.extend(_varint(len(script)))
        without_witness.extend(script)
        without_witness.extend(sequence)

    without_witness.extend(_varint(len(outputs)))

    for amount, script in outputs:
        without_witness.extend(amount.to_bytes(8, 'little'))
        without_witness.extend(_varint(len(script)))
        without_witness.extend(script)

    without_witness.extend(locktime)

    return _reversed(scripts.sha256(scripts.sha256(bytes(without_witness)))).hex(), outputs


def _read_inputs(reader: '_Reader') -> Tuple[List[Tuple[bytes, bytes, bytes]], bool]:
    """
    Read the inputs, taking the segwit marker out of the way if it is there.
    """
    count = reader.varint()
    witness_flag = False

    if count == 0:
        if reader.take(1) != b'\x01':
            raise ValueError('A transaction with no inputs has no segwit flag either')

        witness_flag = True
        count = reader.varint()

    if count == 0:
        raise ValueError('A transaction with no inputs is not one')

    inputs = []

    for _ in range(count):
        outpoint = reader.take(36)
        script = reader.take(reader.varint())
        inputs.append((outpoint, script, reader.take(4)))

    return inputs, witness_flag


def _read_outputs(reader: '_Reader') -> List[Tuple[int, bytes]]:
    """
    Read the outputs, each an amount and the script that locks it.
    """
    count = reader.varint()

    if count == 0:
        raise ValueError('A transaction with no outputs is not one')

    return [(int.from_bytes(reader.take(8), 'little'), reader.take(reader.varint()))
            for _ in range(count)]


class _Reader:
    """
    Walks over a serialized transaction, refusing to read past what is there.
    """

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.at = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > len(self.raw):
            raise ValueError(f'The transaction ends before the {count} bytes expected at {self.at}')

        taken = self.raw[self.at:self.at + count]
        self.at += count

        return taken

    def varint(self) -> int:
        marker = self.take(1)[0]

        if marker < 0xfd:
            return marker

        widths = {0xfd: 2, 0xfe: 4, 0xff: 8}

        return int.from_bytes(self.take(widths[marker]), 'little')

    def done(self) -> None:
        if self.at != len(self.raw):
            raise ValueError(f'The transaction ends at {self.at} with {len(self.raw) - self.at} bytes to spare')


def _serialize_tx(
        inputs: List[Tuple[scanner.Utxo, bytes, List[bytes]]],
        outputs: List[Tuple[int, bytes]],
        include_witness: bool = True
) -> bytearray:
    """
    Serialize a transaction in wire format.
    """
    segwit = include_witness and any(len(witness) > 0 for _, _, witness in inputs)

    tx = bytearray()
    tx.extend(VERSION.to_bytes(4, 'little'))

    if segwit:
        tx.append(SEGWIT_MARKER)
        tx.append(SEGWIT_FLAG)

    tx.extend(_varint(len(inputs)))

    for utxo, script, _ in inputs:
        tx.extend(_reversed(bytes.fromhex(utxo.txid)))
        tx.extend(utxo.output_index.to_bytes(4, 'little'))
        tx.extend(_varint(len(script)))
        tx.extend(script)
        tx.extend(SEQUENCE.to_bytes(4, 'little'))

    tx.extend(_varint(len(outputs)))

    for amount, script in outputs:
        tx.extend(amount.to_bytes(8, 'little'))
        tx.extend(_varint(len(script)))
        tx.extend(script)

    if segwit:
        for _, _, witness in inputs:
            tx.extend(_varint(len(witness)))
            for item in witness:
                tx.extend(_varint(len(item)))
                tx.extend(item)

    tx.extend(LOCKTIME.to_bytes(4, 'little'))
    return tx


def _outpoint_of(utxo: scanner.Utxo) -> bytes:
    """
    Write an unspent output's outpoint the way a transaction carries it.
    """
    return _reversed(bytes.fromhex(utxo.txid)) + utxo.output_index.to_bytes(4, 'little')


def _taproot_sighash(
        input_index: int,
        spent: List[Tuple[bytes, int, bytes, int]],
        outputs: List[Tuple[int, bytes]]
) -> bytes:
    """
    Compute the BIP341 digest signed for a taproot input spent by its key.

    Each entry of spent is the outpoint, the amount and the script of the output being spent,
    and the sequence the input carries.
    """
    # Where BIP143 committed to the one amount being spent, this commits to every input's
    # amount and to the script each one pays, so a signature cannot be replayed against a
    # transaction that lies to the signer about what the other inputs are worth
    message = bytearray()

    message.append(TAPROOT_EPOCH)
    message.append(SIGHASH_DEFAULT)
    message.extend(VERSION.to_bytes(4, 'little'))
    message.extend(LOCKTIME.to_bytes(4, 'little'))

    message.extend(scripts.sha256(b''.join(outpoint for outpoint, _, _, _ in spent)))
    message.extend(scripts.sha256(b''.join(amount.to_bytes(8, 'little') for _, amount, _, _ in spent)))
    message.extend(scripts.sha256(b''.join(_varint(len(paid)) + paid for _, _, paid, _ in spent)))
    message.extend(scripts.sha256(b''.join(sequence.to_bytes(4, 'little') for _, _, _, sequence in spent)))

    outs = bytearray()
    for amount, script in outputs:
        outs.extend(amount.to_bytes(8, 'little'))
        outs.extend(_varint(len(script)))
        outs.extend(script)

    message.extend(scripts.sha256(bytes(outs)))
    message.append(TAPROOT_KEY_PATH_SPEND_TYPE)
    message.extend(input_index.to_bytes(4, 'little'))

    return scripts.tagged_hash(TAPSIGHASH_TAG, bytes(message))


def _taproot_privkey(privkey: bytes, pubkey: bytes) -> bytes:
    """
    Move a derived private key onto the output key that BIP86 pays, which is what spends it.
    """
    # The tweak is defined on the even point, so a derived key whose point has an odd y is
    # negated before it is added to. The parity of what comes out is not this function's to
    # settle: BIP340 signing takes whichever of the two it needs, and either one handed to
    # it yields the same signature
    scalar = int.from_bytes(privkey, 'big')

    if pubkey[0] == ODD_Y_PREFIX:
        scalar = CURVE_ORDER - scalar

    tweak = scripts.tagged_hash(scripts.TAPTWEAK_TAG, pubkey[scripts.X_ONLY_STARTS_AT:])
    tweaked = (scalar + int.from_bytes(tweak, 'big')) % CURVE_ORDER

    return tweaked.to_bytes(SCALAR_LENGTH_IN_BYTES, 'big')


def _serialize_tx_for_segwit_signing(
        input_index: int,
        inputs: List[Tuple[scanner.Utxo, bytes, List[bytes]]],
        outputs: List[Tuple[int, bytes]]
) -> bytearray:
    """
    Serialize a transaction in order to produce the BIP143 digest needed to sign segwit inputs.
    """
    tx = bytearray()
    tx.extend(VERSION.to_bytes(4, 'little'))

    outpoints = bytearray()
    sequences = bytearray()

    for utxo, _, _ in inputs:
        outpoints.extend(_reversed(bytes.fromhex(utxo.txid)))
        outpoints.extend(utxo.output_index.to_bytes(4, 'little'))
        sequences.extend(SEQUENCE.to_bytes(4, 'little'))

    tx.extend(scripts.sha256(scripts.sha256(bytes(outpoints))))
    tx.extend(scripts.sha256(scripts.sha256(bytes(sequences))))

    utxo, script, _ = inputs[input_index]

    tx.extend(_reversed(bytes.fromhex(utxo.txid)))
    tx.extend(utxo.output_index.to_bytes(4, 'little'))
    tx.extend(_varint(len(script)))
    tx.extend(script)
    tx.extend(utxo.amount_in_sat.to_bytes(8, 'little'))
    tx.extend(SEQUENCE.to_bytes(4, 'little'))

    outs = bytearray()
    for amount, script in outputs:
        outs.extend(amount.to_bytes(8, 'little'))
        outs.extend(_varint(len(script)))
        outs.extend(script)

    tx.extend(scripts.sha256(scripts.sha256(bytes(outs))))
    tx.extend(LOCKTIME.to_bytes(4, 'little'))
    return tx


def _varint(number: int) -> bytes:
    """
    Create a script that pushes an integer to the script stack.
    """
    if number <= 0xfc:
        return bytes([number])

    if number <= 0xffff:
        return bytes([0xfd, *number.to_bytes(2, 'little')])

    if number <= 0xffff_ffff:
        return bytes([0xfe, *number.to_bytes(4, 'little')])

    if number <= 0xffff_ffff_ffff_ffff:
        return bytes([0xff, *number.to_bytes(8, 'little')])

    raise ValueError()


def _reversed(array: bytes) -> bytes:
    array = bytearray(array)
    array.reverse()
    return bytes(array)
