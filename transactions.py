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

        for index in range(len(utxos)):
            utxo = utxos[index]

            # Build the inputs for signing: they should all have empty scripts, save for the input that we are signing,
            # which should have the output script of a P2PKH output.
            pubkey = master_key.get_pubkey_from_path(utxo.path.to_list())
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

            privkey = master_key.get_privkey_from_path(utxo.path.to_list())
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
