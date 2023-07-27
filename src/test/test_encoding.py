#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde
import unittest
from algos.ellipticCurveEncodingDecoding import elliptic_curve_encoding, elliptic_curve_decoding
from algos.encodingDecodingOfMultiplaintext import encoding_message_as_multiplaintext, decoding_message_from_multiplaintext
from algos.secp256k1 import Point
import math

class EllipticCurveEncodingTestClass(unittest.TestCase):
    """
    unittest.TestCase for elliptic curve encoding
    """

    def test_from_doc(self):
        """

        :return:
        """
        (x,y) = elliptic_curve_encoding(723700557733226221397318656304299424082937404160253525246609900049430216698)

        self.assertEqual(x, int.from_bytes(bytearray.fromhex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe21"), byteorder='big', signed=False))
        self.assertEqual(y, int.from_bytes(bytearray.fromhex("2af4d53f09f4d4ede3caf3f0e06ccfc0f55289d83fed859ca504d6033bec629b"), byteorder='big', signed=False))

class EncodingMessageAsMultiPlaintextTestClass(unittest.TestCase):
    """
    unittest.TestCase for algorithm 5
    """
    def test_from_doc(self):
        r = encoding_message_as_multiplaintext(int(math.pow(2, 32)) - 1, bytearray("qwertyuioplkjhgfdsazxcvbnm".encode("utf-8")))
        self.assertEqual(len(r), 10)
        self.assertEqual(r[0], 625)
        self.assertEqual(r[1], 7824754)
        self.assertEqual(r[2], 7633269)
        self.assertEqual(r[3], 6909808)
        self.assertEqual(r[4], 7105386)
        self.assertEqual(r[5], 6842214)
        self.assertEqual(r[6], 6583137)
        self.assertEqual(r[7], 8026211)
        self.assertEqual(r[8], 7758446)
        self.assertEqual(r[9], 7143424)

class DecodingMessageFromMultiPlaintextTestClass(unittest.TestCase):
    """
    unittest.TestCase for algorithm 6
    """
    def test_from_doc(self):
        multiplaintext = [625,7824754,7633269,6909808,7105386,6842214,6583137,8026211,7758446,7143424]
        msg = decoding_message_from_multiplaintext(int(math.pow(2, 32)) - 1, multiplaintext)
        self.assertEqual(msg, bytearray("qwertyuioplkjhgfdsazxcvbnm".encode("utf-8")))
        multiplaintextDash = [625,7824754,7633269,6909808,7105386,6842214,6583137,8026211,7758446,7143425]
        with self.assertRaises(AssertionError):
            msg = decoding_message_from_multiplaintext(int(math.pow(2, 32)) - 1, multiplaintextDash)

class DecodingEncodingMessageTestClass(unittest.TestCase):
    """
    unittest.TestCase
    """
    def test_encoding_decoding_combination(self):
        r = encoding_message_as_multiplaintext(int(math.pow(2, 32)) - 1, bytearray("Das ist ein Test".encode("utf-8")))
        msg = decoding_message_from_multiplaintext(int(math.pow(2, 32)) - 1, r)
        self.assertEqual(msg, bytearray("Das ist ein Test".encode("utf-8")))

class EllipticCurveDecodingTestClass(unittest.TestCase):
    """
    unittest.TestCase for elliptic curve decoding
    """

    def test_from_doc(self):
        """

        :return:
        """
        x = bytearray.fromhex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe21")
        y = bytearray.fromhex("2af4d53f09f4d4ede3caf3f0e06ccfc0f55289d83fed859ca504d6033bec629b")

        pt = Point(x,y)

        a = elliptic_curve_decoding(pt)
        self.assertEqual(a,723700557733226221397318656304299424082937404160253525246609900049430216698)
