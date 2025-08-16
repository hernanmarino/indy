#!/usr/bin/env python3
import asyncio
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from typing import List, Optional, Tuple
from unittest import mock

from bip32 import BIP32
from connectrum.client import StratumClient

import indy
import scanner
from descriptors import Path
from indy import MAX_FEE_RATE
from scripts import ScriptType

# Master private key from the BIP32 test vector 1
BIP32_TEST_XPRIV = ('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv'
                    'NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')

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
            asyncio.run(indy.find_utxos(None, master_key, 20, 0, should_batch=True, **settings))

    return Sweep(output.getvalue(), events, broadcast)


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


class TestServerList(unittest.TestCase):
    """
    The bundled list of Electrum servers.
    """

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
                await indy.find_utxos(None, None, 20, 0, None, None, False, True)

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
                asyncio.run(indy.find_utxos(None, master_key, 20, 0, destination, None, False, True))

        self.assertIn('7 sat/vbyte', output.getvalue())


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
