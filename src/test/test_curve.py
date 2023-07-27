#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde
import unittest
from algos.secp256k1 import Point, Curve

class secp256k1CompressTestClass(unittest.TestCase):
    """
    unittest.TestCase to test if the compression of points on the elliptic curve work
    """
    def test_good_cases(self):
        """

        :return:
        """
        curve = Curve()
        compressed_key = bytearray.fromhex("0275788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b")
        x = int.from_bytes(bytearray.fromhex("75788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b"),byteorder="big",signed=False)
        y = int.from_bytes(bytearray.fromhex("664663757d16eff0b993ac12a1ba16ee4784ac08206b12be50f4d954d9d74c88"),byteorder="big",signed=False)
        self.assertEqual(curve.compress(Point(x,y)), compressed_key)

class secp256k1DecompressTestClass(unittest.TestCase):
    """
    unittest.TestCase to test if the decompression of points on the elliptic curve work
    """
    def test_good_cases(self):
        """

        :return:
        """
        curve = Curve()
        compressed_key = bytearray.fromhex("0275788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b")
        x = int.from_bytes(bytearray.fromhex("75788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b"),byteorder="big",signed=False)
        y = int.from_bytes(bytearray.fromhex("664663757d16eff0b993ac12a1ba16ee4784ac08206b12be50f4d954d9d74c88"),byteorder="big",signed=False)
        self.assertEqual(curve.decompress(compressed_key).x, x)
        self.assertEqual(curve.decompress(compressed_key).y, y)

class PointTestClass(unittest.TestCase):
    """
    unittest.Testcase to test if the constructor of Point is working with ints and bytearrays
    """
    def test_equality(self):
        """

        :return:
        """
        xH = bytearray.fromhex("75788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b")
        x = int.from_bytes(xH,byteorder="big",signed=False)
        yH = bytearray.fromhex("664663757d16eff0b993ac12a1ba16ee4784ac08206b12be50f4d954d9d74c88")
        y = int.from_bytes(yH,byteorder="big",signed=False)

        p1 = Point(x,y)
        p2 = Point(xH, yH)
        self.assertEqual(p1,p2)
        self.assertTrue(p1.valid())
        self.assertTrue(p2.valid())

    def test_none(self):
        """

        :return:
        """
        p1 = Point(None,None)
        self.assertFalse(p1.valid())

    def test_compression(self):
        """

        :return:
        """
        compressed_key = bytearray.fromhex("0275788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b")
        x = int.from_bytes(bytearray.fromhex("75788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b"), byteorder="big", signed=False)
        y = int.from_bytes(bytearray.fromhex("664663757d16eff0b993ac12a1ba16ee4784ac08206b12be50f4d954d9d74c88"), byteorder="big", signed=False)
        self.assertEqual(Point(x,y).compress_as_bytearray(), compressed_key)


    def test_valid(self):
        """

        :return:
        """
        xH = bytearray.fromhex("0296EA334615B205F2B75AED751586FBFBFF794B4F96780146E55A11D3ED5447BF")
        yH = bytearray.fromhex("0237A9A3B7738311C6F36D954A8CAB89A697FD8AEF38676D732EC44FB978269F26")

        curve = Curve()

        p1 = curve.decompress(xH)
        p2 = curve.decompress(yH)
        self.assertTrue(p1.valid())
        self.assertTrue(p2.valid())

if __name__ == '__main__':
    unittest.main()