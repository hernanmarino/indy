#!/usr/bin/env python3
from __future__ import annotations

from collections import OrderedDict, deque
from typing import List, Optional

from bip32 import BIP32, HARDENED_INDEX

from scripts import ScriptType

# m: master key
# a: account index
# i: address index
descriptors = {
    # Wallets that took up segwit without leaving the BIP44 path put every script type here:
    # CoolWallet S the P2SH wrapped one, and Bisq, Copay and KoinKeep the native one
    "m/44'/0'/a'/0/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BIP44, external
    "m/44'/0'/a'/1/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BIP44, change
    # Bisq and KoinKeep hold the wallet on the second account and leave the first one empty, so
    # the account range never expands on its own and that wallet falls outside any scan
    "m/44'/0'/1'/0/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BIP44 account 1, external
    "m/44'/0'/1'/1/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BIP44 account 1, change
    "m/49'/0'/a'/0/i": [ScriptType.COMPAT],  # BIP49, external
    "m/49'/0'/a'/1/i": [ScriptType.COMPAT],  # BIP49, change
    "m/84'/0'/a'/0/i": [ScriptType.SEGWIT],  # BIP84, external
    "m/84'/0'/a'/1/i": [ScriptType.SEGWIT],  # BIP84, change
    "m/0'/0'/i'": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # Bitcoin Core
    # Electrum hangs the addresses of a standard wallet right off the master key. Its segwit
    # wallets sit at m/0', which the two rows below already reach
    'm/0/i': [ScriptType.LEGACY],  # Electrum standard, external
    'm/1/i': [ScriptType.LEGACY],  # Electrum standard, change
    "m/0'/0/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BRD/Hodl/Coin/Multibit external
    "m/0'/1/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BRD/Hodl/Coin/Multibit change
    "m/44'/0'/2147483647'/0/i": [ScriptType.LEGACY],  # Samourai ricochet, BIP44, external
    "m/44'/0'/2147483647'/1/i": [ScriptType.LEGACY],  # Samourai ricochet, BIP44, change
    "m/49'/0'/2147483647'/0/i": [ScriptType.COMPAT],  # Samourai ricochet, BIP49, external
    "m/49'/0'/2147483647'/1/i": [ScriptType.COMPAT],  # Samourai ricochet, BIP49, change
    "m/84'/0'/2147483647'/0/i": [ScriptType.SEGWIT],  # Samourai ricochet, BIP84, external
    "m/84'/0'/2147483647'/1/i": [ScriptType.SEGWIT],  # Samourai ricochet, BIP84, change
    "m/84'/0'/2147483646'/0/i": [ScriptType.SEGWIT],  # Samourai post-mix, external
    "m/84'/0'/2147483646'/1/i": [ScriptType.SEGWIT],  # Samourai post-mix, change
    "m/84'/0'/2147483645'/0/i": [ScriptType.SEGWIT],  # Samourai pre-mix, external
    "m/84'/0'/2147483645'/1/i": [ScriptType.SEGWIT],  # Samourai pre-mix, change
    "m/84'/0'/2147483644'/0/i": [ScriptType.SEGWIT],  # Samourai bad-bank, external
    "m/84'/0'/2147483644'/1/i": [ScriptType.SEGWIT],  # Samourai bad-bank, change
}


class Path:
    """
    Derivation path from a master key that may have a variable account number, and a variable index number.
    """

    def __init__(self, path: str):
        self.path = path

    def has_variable_account(self) -> bool:
        """
        Whether this path has the account level as a free variable.
        """
        return self.path.find('a') >= 0

    def has_variable_index(self) -> bool:
        """
        Whether this path has the index level as a free variable.
        """
        return self.path.find('i') >= 0

    def to_list(self, index: int = None, account: int = None) -> List[int]:
        """
        Transform this path into a list of valid derivation indexes.
        """
        # replace the placeholders
        path = self.path.replace('a', str(account)).replace('i', str(index))
        parts = path.split('/')[1:]

        # compute the derivation indexes
        indexes = []
        for part in parts:
            if part.endswith("'"):
                indexes.append(HARDENED_INDEX + int(part[:-1]))
            else:
                indexes.append(int(part))
        return indexes

    def with_account(self, account: int) -> Path:
        """
        Get a new path with a fixed account.
        """
        return Path(self.path.replace('a', str(account)))

    def with_index(self, index: int) -> Path:
        """
        Get a new path with a fixed index.
        """
        return Path(self.path.replace('i', str(index)))

    def __eq__(self, other):
        if isinstance(other, Path):
            return self.path == other.path
        return NotImplemented

    def __hash__(self):
        return hash(self.path)


class Script:
    """
    Data needed to spend a script.
    """

    def __init__(self, program: bytes, index: int, account: int, descriptor: DescriptorScriptIterator):
        self.program = program
        self.index = index
        self.account = account
        self.descriptor = descriptor

    def type(self) -> ScriptType:
        return self.descriptor.script_type

    def path_with_account(self) -> Path:
        return self.descriptor.path.with_account(self.account)

    def full_path(self) -> Path:
        return self.path_with_account().with_index(self.index)

    def set_as_used(self) -> None:
        self.descriptor.found_used_script(self)


class DescriptorScriptIterator:
    """
    Iterator that can traverse the all the possible scripts generated by a descriptor (ie. a path and script type pair).
    """

    def __init__(self, path: Path, script_type: ScriptType, address_gap: int, account_gap: int):
        self.path = path
        self.script_type = script_type
        self.address_gap = address_gap
        self.account_gap = account_gap
        self.index = 0
        self.account = 0
        self.max_index = address_gap if path.has_variable_index() else 0
        self.max_account = account_gap if path.has_variable_account() else 0
        self.used_accounts = set()
        self.priority_pairs = OrderedDict()
        self.yielded_pairs = set()
        self.total_scripts = (self.max_index + 1) * (self.max_account + 1)

    def _script_at(self, master_key: BIP32, index: int, account: int) -> Script:
        """
        Render the script at a specific index and account pair.
        """
        pubkey = master_key.get_pubkey_from_path(self.path.to_list(index, account))
        script = self.script_type.build_output_script(pubkey)

        return Script(script, index, account, self)

    def _next_pair(self) -> None:
        """
        Compute the next pair of index and account positions that we should explore.
        """
        # Since traversing the entire [0; MAX_INDEX] x [0; MAX_ACCOUNT] space of combinations might take a while, we
        # walk the (index, account) grid in diagonal order. This order prioritizes the most probable combinations
        # (ie. low index, low account), while letting us explore a large space in the long run.
        #
        #           0     1     2
        #         ↙     ↙     ↙
        #    (0,0) (1,0) (2,0)  3
        #   ↙     ↙     ↙     ↙
        #    (0,1) (1,1) (2,1)  4
        #   ↙     ↙     ↙     ↙
        #    (0,2) (1,2) (2,2)  5
        #   ↙     ↙     ↙     ↙
        #    (0,3) (1,3) (2,3)
        #   ↙     ↙     ↙

        if self.index == 0 or self.account == self.max_account:
            # if we reached the border, start in the next diagonal
            diagonal_total = self.index + self.account + 1
            self.index = min(diagonal_total, self.max_index)
            self.account = diagonal_total - self.index
        else:
            # go down the diagonal
            self.index -= 1
            self.account += 1

    def next_script(self, master_key: BIP32) -> Optional[Script]:
        """
        Fetch the next script for the current descriptor, without ever yielding the same pair twice.
        """
        # Scripts are handed out before their results come back, so a pair that the grid already
        # yielded can be queued again as a priority pair. Skipping the repeats here keeps that from
        # reaching the caller, whenever the results happen to arrive
        while True:
            script = self._next_script(master_key)
            if script is None:
                return None

            pair = (script.index, script.account)
            if pair in self.yielded_pairs:
                continue

            self.yielded_pairs.add(pair)
            return script

    def _next_script(self, master_key: BIP32) -> Optional[Script]:
        """
        Fetch the next candidate script for the current descriptor.
        """
        # if there's any priority pairs, explore the first one
        for account, indexes in list(self.priority_pairs.items()):
            if indexes:
                index = indexes.popleft()
                return self._script_at(master_key, index, account)
            else:
                del self.priority_pairs[account]

        # if we are off the grid, then we are done
        if self.account > self.max_account:
            return None

        # generate the script for the current pair in the grid
        response = self._script_at(master_key, self.index, self.account)

        # and compute the next pair in the grid to explore
        self._next_pair()
        while self.account in self.used_accounts:
            self._next_pair()

        return response

    def found_used_script(self, script: Script) -> None:
        """
        Update the priority scripts to process, knowing that a particular script was used.
        """
        # stop exploring the current account during the grid search
        self.used_accounts.add(script.account)

        if script.account not in self.priority_pairs:
            self.priority_pairs[script.account] = deque()

        # extend the priority list of pairs to explore with enough indexes so that the next address gap is covered
        if self.path.has_variable_index():
            missing_indexes = self.priority_pairs[script.account]
            last_index = missing_indexes[-1] if missing_indexes else script.index
            new_indexes = range(last_index + 1, script.index + self.address_gap + 1)
            missing_indexes.extend(new_indexes)
            self.total_scripts += len([i for i in new_indexes if i > self.max_index])

        # extend the priority list of pairs to explore with enough accounts so that the next account gap is covered
        while (self.path.has_variable_account()
               and self.max_account <= script.account + self.account_gap):
            self.max_account += 1
            self.total_scripts += self.max_index + 1
            current_diagonal = self.index + self.account
            missing_indexes = deque(range(current_diagonal - self.max_account))
            self.priority_pairs[self.max_account] = missing_indexes

    def has_priority_scripts(self) -> bool:
        """
        Whether this descriptor should be prioritized because it's exploring a used account path.
        """
        for account, indexes in self.priority_pairs.items():
            if indexes:
                return True
        return False


class ScriptIterator:
    """
    Iterator that can traverse all the possible scripts of all the possible descriptors.
    """

    def __init__(self, master_key: BIP32, address_gap: int, account_gap: int):
        self.master_key = master_key
        self.index = 0
        self.descriptors = []
        self.last_descriptor = None
        for path, types in descriptors.items():
            for type in types:
                self.descriptors.append(DescriptorScriptIterator(Path(path), type, address_gap, account_gap))

    def _next_descriptor_script(self) -> Optional[Script]:
        """
        Fetch the next script from the next descriptor.
        """
        if self.last_descriptor and self.last_descriptor.has_priority_scripts():
            iter = self.last_descriptor.next_script(self.master_key)
            if iter:
                return iter

        self.last_descriptor = self.descriptors[self.index]
        iter = self.last_descriptor.next_script(self.master_key)

        self.index += 1
        if self.index >= len(self.descriptors):
            self.index = 0

        return iter

    def next_script(self) -> Optional[Script]:
        """
        Fetch the next script, cycling the descriptors in order to explore all of them progressively.
        """
        skipped = 0

        while skipped < len(self.descriptors):
            iter = self._next_descriptor_script()
            if iter:
                return iter
            skipped += 1

        return None

    def total_scripts(self) -> int:
        """
        Compute the total number of scripts that were or will be explored.
        """
        return sum([d.total_scripts for d in self.descriptors])
