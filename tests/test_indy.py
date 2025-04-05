#!/usr/bin/env python3
import asyncio
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from typing import List, Tuple
from unittest import mock

from connectrum.client import StratumClient

import indy

# Master private key from the BIP32 test vector 1
BIP32_TEST_XPRIV = ('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv'
                    'NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')


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
            return indy.read_servers()
        finally:
            os.chdir(previous)

    def _read_servers_through(self, module_path: str) -> List[dict]:
        with mock.patch.object(indy, '__file__', module_path):
            return self._read_servers_from(os.path.dirname(module_path))

    def test_every_server_declares_a_host_and_a_port(self) -> None:
        for server in indy.read_servers():
            self.assertIn('host', server)
            self.assertIn('port', server)


if __name__ == '__main__':
    unittest.main()
