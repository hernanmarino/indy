#!/usr/bin/env python3
import argparse
import asyncio
import json
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
        not args.no_batching
    ))


def _fee_rate_in_sat_per_vbyte(fee_rate_in_btc_per_kb: float) -> int:
    """
    Convert the fee rate an electrum server reports into satoshis per virtual byte.
    """
    # The rate arrives as a float, so it is read as the decimal it prints as: scaling the binary
    # value drops whole satoshis
    return int(Decimal(str(fee_rate_in_btc_per_kb)) * SATOSHIS_PER_BITCOIN / BYTES_PER_KILOBYTE)


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
        should_batch: bool
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
        fee_rate_in_btc_per_kb = await client.RPC('blockchain.estimatefee', 1)

        if fee_rate_in_btc_per_kb == -1:
            print('🔁  Couldn\'t fetch fee rates, try again with manual fee rates using `--fee-rate`')
            client.close()
            return

        fee_rate = _fee_rate_in_sat_per_vbyte(fee_rate_in_btc_per_kb)

        print(f'🚌  Fetched next-block fee rate of {fee_rate} sat/vbyte')

    tx_without_fee = transactions.Transaction(master_key, utxos, address, balance)
    fee = tx_without_fee.virtual_size() * fee_rate
    tx = transactions.Transaction(master_key, utxos, address, balance - fee)
    bin_tx = tx.to_bytes()

    print('👇  This transaction sweeps all funds to the address provided')
    print()
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
