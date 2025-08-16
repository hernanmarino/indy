#!/usr/bin/env python3
import argparse
import asyncio
import json
import math
import os
import random
from decimal import Decimal
from typing import List, Optional

import connectrum
from bip32 import BIP32
from connectrum.client import StratumClient
from connectrum.svr_info import ServerInfo
from mnemonic import Mnemonic

import scanner
import transactions

# Offered to the server as a range, since not every server speaks the newest protocol
ELECTRUM_PROTOCOL_VERSIONS = ['1.4', '1.4.2']

SATOSHIS_PER_BITCOIN = 10 ** 8
BYTES_PER_KILOBYTE = 1_000

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

    parser.add_argument('key', help='master key to sweep, formats: mnemonic, xpriv or xpub')
    parser.add_argument('--passphrase', metavar='<pass>', default='',
                        help='optional secret phrase necessary to decode the mnemonic')

    sweep_tx = parser.add_argument_group('sweep transaction')

    sweep_tx.add_argument('--address', metavar='<address>',
                          help='craft a transaction sending all funds to this address')
    sweep_tx.add_argument('--broadcast', default=False, action='store_true',
                          help='if present broadcast the transaction to the network')
    sweep_tx.add_argument('--fee-rate', metavar='<rate>', type=int,
                          help='fee rate to use in sat/vbyte (default: next block fee)')
    sweep_tx.add_argument('--allow-high-fee', default=False, action='store_true',
                          help=f'allow a fee above {int(100 * MAX_FEE_SHARE_OF_BALANCE)}%% of the funds found')

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

    args = parser.parse_args()

    master_key = parse_key(args.key, args.passphrase)

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
        args.allow_high_fee
    ))


def _fee_rate_in_sat_per_vbyte(fee_rate_in_btc_per_kb: float) -> int:
    """
    Convert the fee rate an electrum server reports into satoshis per virtual byte.
    """
    # The rate arrives as a float, so it is read as the decimal it prints as: scaling the binary
    # value drops whole satoshis
    return int(Decimal(str(fee_rate_in_btc_per_kb)) * SATOSHIS_PER_BITCOIN / BYTES_PER_KILOBYTE)


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


def parse_key(key: str, passphrase: str) -> BIP32:
    """
    Try to parse an extended key, whether it is in xpub, xpriv or mnemonic format.
    """
    try:
        private_key = BIP32.from_xpriv(key)
        print('🔑  Read master private key successfully')
        return private_key
    except Exception:
        pass

    try:
        public_key = BIP32.from_xpub(key)
        print('🔑  Read master public key successfully')
        return public_key
    except Exception:
        pass

    try:
        language = Mnemonic.detect_language(key)
        seed = Mnemonic(language).to_seed(key, passphrase=passphrase)
        private_key = BIP32.from_seed(seed)
        print('🔑  Read mnemonic successfully')
        return private_key
    except Exception:
        pass

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
        allow_high_fee: bool = False
):
    """
    Connect to an electrum server and find all the UTXOs spendable by a master key.
    """
    print('⏳  Connecting to electrum server, this might take a while')

    client = StratumClient(my_proto_version=ELECTRUM_PROTOCOL_VERSIONS)
    await client.connect(server, disable_cert_verify=True)

    print('🌍  Connected to electrum server successfully')

    utxos = await scanner.scan_master_key(client, master_key, address_gap, account_gap, should_batch)

    if len(utxos) == 0:
        print('😔  Didn\'t find any unspent outputs')
        client.close()
        return

    balance = sum([utxo.amount_in_sat for utxo in utxos])
    print(f'💸  Total spendable balance found: {balance} sats')

    if master_key.master_privkey is None:
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


    print('👇  This transaction sweeps all funds to the address provided')
    print(bin_tx.hex())
    print()

    if not should_broadcast:
        print('📋  Copy this transaction and broadcast it manually to the network, or re-run with `--broadcast`')
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
