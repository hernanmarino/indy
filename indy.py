#!/usr/bin/env python3
import argparse
import asyncio
import getpass
import json
import math
import os
import random
from decimal import Decimal
from typing import List, Optional

import base58
import coincurve
import connectrum
from bip32 import BIP32
from connectrum.client import StratumClient
from connectrum.svr_info import ServerInfo
from mnemonic import Mnemonic

import scanner
import scripts
import transactions

# Offered to the server as a range, since not every server speaks the newest protocol
ELECTRUM_PROTOCOL_VERSIONS = ['1.4', '1.4.2']

SATOSHIS_PER_BITCOIN = 10 ** 8
BYTES_PER_KILOBYTE = 1_000

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
        description='Find and sweep all the funds from a mnemonic or bitcoin key, regardless of the derivation path or '
                    'address format used.'
    )

    parser.add_argument('key', nargs='?', default=None,
                        help='master key to sweep, formats: mnemonic, xpriv or xpub '
                             '(asked for out of sight if left off)')
    passphrase_source = parser.add_mutually_exclusive_group()
    passphrase_source.add_argument('--passphrase', metavar='<pass>', default='',
                                   help='optional secret phrase necessary to decode the mnemonic')
    passphrase_source.add_argument('--ask-passphrase', default=False, action='store_true',
                                   help='ask for the passphrase out of sight instead of reading it here')
    parser.add_argument('--allow-invalid-checksum', default=False, action='store_true',
                        help='derive from a mnemonic whose BIP39 checksum does not match')

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

    master_key = parse_key(key, passphrase, args.allow_invalid_checksum)

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
        args.insecure
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


def _checksum_matches(words: str) -> bool:
    """
    Whether these words carry a valid BIP39 checksum in any of the wordlists.
    """
    # Several wordlists share words, and detect_language settles on the first that fits them all,
    # which is not always the one the phrase was written in: the BIP39 test vector reads as French
    return any(Mnemonic(language).check(words) for language in Mnemonic.list_languages())


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


def parse_key(key: str, passphrase: str, allow_invalid_checksum: bool = False) -> BIP32:
    """
    Try to parse an extended key, whether it is in xpub, xpriv or mnemonic format.
    """
    if _is_private_key(key):
        try:
            private_key = BIP32.from_xpriv(key)
            print('🔑  Read master private key successfully')
            return private_key
        except Exception:
            pass

    if _is_public_key(key):
        try:
            public_key = BIP32.from_xpub(key)
            print('🔑  Read master public key successfully')
            return public_key
        except Exception:
            pass

    try:
        language = Mnemonic.detect_language(key)
    except Exception:
        language = None

    if language is not None:
        if not allow_invalid_checksum and not _checksum_matches(key):
            raise ValueError(
                'Those words don\'t add up: the BIP39 checksum doesn\'t match, which usually means a '
                'word was mistyped or two were swapped. An Electrum seed phrase uses the same words '
                'but is not BIP39, and lands here too. Pass `--allow-invalid-checksum` to derive from '
                'the words as given anyway.'
            )

        seed = Mnemonic(language).to_seed(key, passphrase=passphrase)
        private_key = BIP32.from_seed(seed)
        print('🔑  Read mnemonic successfully')
        return private_key

    raise ValueError('The key is invalid or the format isn\'t recognized. Make sure it\'s a mnemonic, xpriv or xpub.')


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
        insecure: bool = False
):
    """
    Connect to an electrum server and find all the UTXOs spendable by a master key.
    """
    if master_key.master_privkey is None:
        print('⛔️  Every derivation path this knows of starts at a hardened level, and a public key')
        print('    cannot derive those. Recovering from an xpub needs the private key for now')
        return

    if not insecure and server.protocols != {'s'}:
        print('⛔️  That server would be reached over plain TCP, putting every address this looks up')
        print('    on the wire in the clear. Pass `--insecure` if that is what you want')
        return

    print('⏳  Connecting to electrum server, this might take a while')

    client = StratumClient(my_proto_version=ELECTRUM_PROTOCOL_VERSIONS)
    await client.connect(server, disable_cert_verify=insecure)

    print('🌍  Connected to electrum server successfully')

    utxos = await scanner.scan_master_key(client, master_key, address_gap, account_gap, should_batch)

    if len(utxos) == 0:
        print('😔  Didn\'t find any unspent outputs')
        client.close()
        return

    balance = sum([utxo.amount_in_sat for utxo in utxos])
    print(f'💸  Total spendable balance found: {balance} sats')

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

    print('👇  This transaction sweeps all funds to the address provided')
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
