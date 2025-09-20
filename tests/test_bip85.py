#!/usr/bin/env python3
import unittest
from unittest import mock

from bip32 import BIP32

import bip85

# The master key every BIP85 test vector derives from
VECTOR_ROOT = ('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8km'
               'baLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')

# The two generic vectors: the key a path derives and the entropy it stretches to
GENERIC_VECTORS = [
    (0, 0, 'cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0',
     'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0'
     '0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7'),
    (0, 1, '503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba',
     '70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872'
     '218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e'),
]

# The BIP39 vectors, by word count: the entropy the path yields and the words it spells
MNEMONIC_VECTORS = [
    (12, '6250b68daf746d12a24d58b4787a714b',
     'girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose'),
    (18, '938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc',
     'near account window bike charge season chef number sketch tomorrow excuse sniff '
     'circle vital hockey outdoor supply token'),
    (24, 'ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f',
     'puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget '
     'divorce twin tonight reason outdoor destroy simple truth cigar social volcano'),
]

# The WIF vector, which Bitcoin Core takes as an hdseed
WIF_ENTROPY = '7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1'
WIF = 'Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp'

# The XPRV vector. What the standard publishes as its entropy is the SECOND half of the
# sixty four bytes: an xprv child lays the chain code down first and the private key after,
# and it is the private key that gets printed. The WIF vector above publishes the first half
XPRV_SECRET = 'ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682'
XPRV = ('xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGX'
        'MzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX')


def _root() -> BIP32:
    return BIP32.from_xpriv(VECTOR_ROOT)


class TestEntropy(unittest.TestCase):
    """
    The entropy a path stretches to, which every application is cut out of.
    """

    def test_reproduces_the_generic_vectors(self) -> None:
        for app, index, privkey, entropy in GENERIC_VECTORS:
            with self.subTest(app=app, index=index):
                whole = bip85.hardened([bip85.PURPOSE, app, index])
                self.assertEqual(_root().get_privkey_from_path(whole).hex(), privkey)
                self.assertEqual(bip85.entropy(_root(), [app, index]).hex(), entropy)


class TestMnemonicChildren(unittest.TestCase):
    """
    The BIP39 application, which is the one a wallet is usually restored from.
    """

    def test_reproduces_the_words_of_every_vector(self) -> None:
        for words, entropy, phrase in MNEMONIC_VECTORS:
            with self.subTest(words=words):
                self.assertEqual(bip85.mnemonic_child(_root(), words, 0), phrase)

    def test_the_entropy_is_cut_to_the_length_that_word_count_takes(self) -> None:
        for words, entropy, _ in MNEMONIC_VECTORS:
            with self.subTest(words=words):
                cut = bip85.entropy(_root(), [bip85.MNEMONIC_APP, bip85.ENGLISH, words, 0])
                self.assertEqual(cut[:bip85.WORD_COUNTS[words]].hex(), entropy)

    def test_the_root_of_a_word_child_comes_from_the_words_and_not_the_entropy(self) -> None:
        # The one error the official vectors do not catch. The entropy spells the words; the
        # key comes from stretching those words the way BIP39 does. Building the key out of
        # the entropy bytes gives another wallet entirely, and every vector above stays green
        for words, entropy, phrase in MNEMONIC_VECTORS:
            with self.subTest(words=words):
                child = bip85.child_root(_root(), words, 0)
                from_the_words = BIP32.from_seed(bip85.Mnemonic.to_seed(phrase))
                from_the_bytes = BIP32.from_seed(bytes.fromhex(entropy))

                self.assertEqual(child.get_xpriv(), from_the_words.get_xpriv())
                self.assertNotEqual(child.get_xpriv(), from_the_bytes.get_xpriv())


class TestKeyChildren(unittest.TestCase):
    """
    The two applications that hand over a key rather than words.
    """

    def test_the_xprv_child_matches_the_vector_and_not_its_entropy(self) -> None:
        # The standard lays the chain code down before the private key, which is the other way
        # round from BIP32. Seeding from these bytes builds a different wallet that looks fine
        self.assertEqual(bip85.entropy(_root(), [bip85.XPRV_APP, 0])[32:].hex(), XPRV_SECRET)
        self.assertEqual(bip85.xprv_child(_root(), 0).get_xpriv(), XPRV)

    def test_the_halves_of_an_xprv_child_are_not_swapped(self) -> None:
        # Laying the private key down first and the chain code after builds a wallet that
        # reads as perfectly valid and is somebody else's. The published entropy is the
        # second half, so the chain code is the one that never appears in the vector
        cut = bip85.entropy(_root(), [bip85.XPRV_APP, 0])
        child = bip85.xprv_child(_root(), 0)

        self.assertEqual(child.chaincode, cut[:32])
        self.assertEqual(child.privkey, cut[32:])
        self.assertNotEqual(child.chaincode, child.privkey)

    def test_the_xprv_child_is_a_root_this_program_can_place(self) -> None:
        # Depth, fingerprint and index have to be nought, or reading the key back turns it
        # down for sitting somewhere this cannot look under
        child = bip85.xprv_child(_root(), 0)

        self.assertEqual(child.depth, 0)
        self.assertEqual(child.index, 0)
        self.assertEqual(child.parent_fingerprint, bytes(4))

    def test_the_wif_child_matches_the_vector(self) -> None:
        self.assertEqual(bip85.entropy(_root(), [bip85.WIF_APP, 0])[:32].hex(), WIF_ENTROPY)
        self.assertEqual(bip85.wif_child(_root(), 0), WIF)

    def test_the_wif_child_seeds_the_wallet_bitcoin_core_builds(self) -> None:
        # Core takes those 32 bytes as its hdseed, so the wallet is the one seeded by them
        self.assertEqual(bip85.hdseed_root(_root(), 0).get_xpriv(),
                         BIP32.from_seed(bytes.fromhex(WIF_ENTROPY)).get_xpriv())


class TestAKeyTheCurveHasNoPointFor(unittest.TestCase):
    """
    What happens at an index whose entropy is not a usable key, which the standard says to
    pass over. No real index reaches it, so it is forced here.
    """

    # The order of secp256k1, written out rather than read from the code under test: taking
    # it from there lets the bound move and keeps this green while n becomes a valid key
    ORDER = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe_baae_dce6_af48_a03b_bfd2_5e8c_d036_4141

    # A usable chain code first and an unusable key after, so a guard that looked at the
    # wrong half of the entropy would not be mistaken for one that works
    OUTSIDE = bytes([1]) * 32 + ORDER.to_bytes(32, 'big')

    def test_the_bound_is_the_order_of_the_curve(self) -> None:
        self.assertEqual(bip85.CURVE_ORDER, self.ORDER)

    def test_a_secret_outside_the_curve_is_turned_down(self) -> None:
        # The xprv child reads the second half of the entropy and the other two the first,
        # so each is fed a payload whose own half is the unusable one
        for derive, payload in [(bip85.xprv_child, self.OUTSIDE),
                                (bip85.wif_child, self.OUTSIDE[32:] + bytes([1]) * 32),
                                (bip85.hdseed_root, self.OUTSIDE[32:] + bytes([1]) * 32)]:
            with self.subTest(derive=derive.__name__):
                with mock.patch.object(bip85, 'entropy', lambda *args, p=payload: p):
                    with self.assertRaises(bip85.UnusableChild):
                        derive(_root(), 0)

    def test_an_unusable_form_is_left_out_and_not_moved_to_another_index(self) -> None:
        # The standard says to pass over such a child. Deriving the next index instead hands
        # back a wallet of a different index under the name of this one, without a word
        real = bip85.entropy

        def broken_only_at_this_index(root, path):
            return self.OUTSIDE if path[-1] == 0 else real(root, path)

        with mock.patch.object(bip85, 'entropy', broken_only_at_this_index):
            forms = dict(bip85.children(_root(), 0))

        self.assertNotIn('xprv', forms)
        self.assertNotIn(bip85.xprv_child(_root(), 1).get_xpriv(),
                         [root.get_xpriv() for root in forms.values()])

        # The other key form of that same index is usable and has to survive. Passing over
        # both of them together would satisfy everything above and lose a wallet that is
        # there, which is the whole failure this guard exists to avoid
        self.assertIn('wif', forms)
        self.assertEqual(sorted(forms), ['12w', '18w', '24w', 'wif'])

    def test_only_that_form_is_passed_over_and_not_the_whole_index(self) -> None:
        # The word children are cut from entropy of their own, so one unusable key at an
        # index says nothing about the other four wallets hiding there
        real = bip85.entropy

        def only_the_key_apps_are_broken(root, path):
            if path[0] == bip85.XPRV_APP:
                return self.OUTSIDE

            if path[0] == bip85.WIF_APP:
                return self.OUTSIDE[32:] + bytes([1]) * 32

            return real(root, path)

        with mock.patch.object(bip85, 'entropy', only_the_key_apps_are_broken):
            forms = [form for form, _ in bip85.children(_root(), 0)]

        self.assertEqual(forms, ['12w', '18w', '24w'])


class TestEveryFormOfChild(unittest.TestCase):
    """
    What one index of one seed hides, taken together.
    """

    def test_an_index_hides_one_child_of_each_form(self) -> None:
        children = bip85.children(_root(), 0)

        self.assertEqual([form for form, _ in children], ['12w', '18w', '24w', 'xprv', 'wif'])

    def test_every_form_is_wired_to_the_derivation_it_is_named_after(self) -> None:
        # This is the function the rest of the program calls, and the tests above only
        # reach the pieces it is built out of. Crossing two of them here, or seeding one
        # from the entropy, leaves five distinct keys under five correct labels, and every
        # other test in this file green, while the wallet under each name is the wrong one
        for index in [0, 7]:
            expected = {
                '12w': bip85.child_root(_root(), 12, index),
                '18w': bip85.child_root(_root(), 18, index),
                '24w': bip85.child_root(_root(), 24, index),
                'xprv': bip85.xprv_child(_root(), index),
                'wif': bip85.hdseed_root(_root(), index),
            }

            for form, root in bip85.children(_root(), index):
                with self.subTest(index=index, form=form):
                    self.assertEqual(root.get_xpriv(), expected[form].get_xpriv())

    def test_no_two_forms_of_an_index_are_the_same_wallet(self) -> None:
        keys = {root.get_xpriv() for _, root in bip85.children(_root(), 0)}

        self.assertEqual(len(keys), 5)

    def test_every_form_follows_the_index_it_was_asked_for(self) -> None:
        # Compared form by form, not as two sets: one form that ignores the index while the
        # other four follow it still leaves the two sets disjoint, and that one form is how
        # an index nobody asked for comes back wearing the name of the one they did
        first = dict(bip85.children(_root(), 0))
        second = dict(bip85.children(_root(), 1))

        self.assertEqual(sorted(first), sorted(second))

        for form in first:
            with self.subTest(form=form):
                self.assertNotEqual(first[form].get_xpriv(), second[form].get_xpriv())
