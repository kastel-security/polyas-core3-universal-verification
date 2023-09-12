#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel

"""
Module for working with secp256k1 Curve
"""
import math
import gmpy2 as gmpy

from .TonelliShanks import tonelli


# Some constants for secp256k1
secp256k1_p = int.from_bytes(bytearray.fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), byteorder='big', signed=False)
secp256k1_gx = int.from_bytes(bytearray.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), byteorder='big', signed=False)
secp256k1_gy = int.from_bytes(bytearray.fromhex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"), byteorder='big', signed=False)
secp256k1_g = (secp256k1_gx, secp256k1_gy)

secp256k1_a = 0
secp256k1_b = 7
secp256k1_q = int.from_bytes(bytearray.fromhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), byteorder='big', signed=False)


secp256k1_k = 80
secp256k1_messageUpperBound = math.floor(secp256k1_p / secp256k1_k)

# From https://github.com/user8547/fast-ecc-python


class Point:
    """
    Class for a point on a elliptic curve
    """
    def __init__(self, x, y):

        if x is None:
            self.x = None
        elif isinstance(x, int):
            self.x = x
        elif isinstance(x, bytearray):
            self.x = int.from_bytes(x, byteorder="big", signed=False)
        else:
            raise ValueError("Point contruction TypeError. x is {type(x)}")

        if y is None:
            self.y = None
        elif isinstance(y, int):
            self.y = y
        elif isinstance(y, bytearray):
            self.y = int.from_bytes(y, byteorder="big", signed=False)
        else:
            raise ValueError("Point contruction TypeError. y is {type(y)")

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def compress_as_bytearray(self):
        """

        :return:
        """
        secp256k1 = Curve()
        res = secp256k1.compress(self)
        return res

    def compress_as_int(self):
        """

        :return:
        """
        res = self.compress_as_bytearray()
        return int.from_bytes(res, byteorder="big", signed=False)

    def valid(self):
        """

        :return:
        """
        secp256k1 = Curve()
        return secp256k1.valid(self)

    def add(self, p):
        """

        :param p:
        :return:
        """
        secp256k1 = Curve()
        return secp256k1.add(self, p)

    def inv(self):
        """

        :return:
        """
        secp256k1 = Curve()
        return secp256k1.inv(self)

    def dbl(self):
        """

        :return:
        """
        secp256k1 = Curve()
        return secp256k1.dbl(self)

    def mul(self, k):
        """

        :param k:
        :return:
        """
        secp256k1 = Curve()
        return secp256k1.mul(self, k)


class Curve():
    """
    Class for a elliptic curve

    Encapsulates all functions running in the curve
    """
    def __init__(self):
        # curve parameters for secp256k1
        # http://perso.univ-rennes1.fr/sylvain.duquesne/master/standards/sec2_final.pdf
        self.a = secp256k1_a
        self.b = secp256k1_b
        self.p = secp256k1_p
        self.gx = secp256k1_gx
        self.gy = secp256k1_gy
        self.g = Point(self.gx, self.gy)
        self.q = secp256k1_q

    def valid(self, P: Point) -> bool:
        """

        :param P: Point to be validated
        :return:
        """

        if P.x is None:
            return False

        return P.y**2 % self.p == (pow(P.x, 3, self.p) + self.a * P.x + self.b) % self.p

    def decompress(self, compressed: bytearray) -> Point:
        """

        :param  compressed: Point compressed as bytearray
        :return: the decompressed point
        """

        assert isinstance(compressed, bytearray)

        byte = compressed[0]

        # point at infinity
        if byte == 0x00:
            return Point(None, None)

        xP = int.from_bytes(compressed[1:], byteorder="big", signed=False)
        ysqr = (pow(xP, 3, self.p) + self.a * xP + self.b) % self.p
        assert self.p % 4 == 3
        yP = tonelli(ysqr, self.p)

        if yP % 2:
            if byte == 0x03:
                return Point(xP, yP)
            if byte == 0x02:
                return Point(xP, -yP % self.p)
            raise ValueError("A compressed point starts with 0x02 or 0x03")
        else:
            if byte == 0x02:
                return Point(xP, yP)
            if byte == 0x03:
                return Point(xP, -yP % self.p)
            raise ValueError("A compressed point starts with 0x02 or 0x03")

    def compress(self, P: Point) -> bytearray:
        """

        :param P: Point to be compressed
        :return: Point compressed as bytearray
        """
        assert isinstance(P, Point)

        if P.x is None:
            return bytearray.fromhex("\x00" + "\x00" * 32)

        result = bytearray()
        assert isinstance(P.y, int)
        if P.y % 2:
            result.append(0x03)
        else:
            result.append(0x02)
        result.extend(int.to_bytes(P.x, 32, byteorder="big", signed=False))
        return result

    def inv(self, P: Point) -> Point:
        """

        :param P: Point to be inverted
        :return: inverted point
        """
        assert isinstance(P, Point)

        if P.x is None:
            return [None, None]

        R = Point(P.x, -P.y % self.p)
        return R

    def add(self, P: Point, Q: Point) -> Point:
        """

        :param P:
        :param Q:
        :return:
        """
        assert isinstance(P, Point)
        assert isinstance(Q, Point)

        # P+P=2P
        if P == Q:
            return self.dbl(P)

        # P+0=P
        if P.x is None:
            return Q
        if Q.y is None:
            return P

        # P+-P=0
        if Q == self.inv(P):
            return Point(None, None)

        s = (P.y - Q.y) * int(gmpy.invert(P.x - Q.x, self.p)) % self.p
        xR = (pow(s, 2, self.p) - P.x - Q.x) % self.p
        yR = (-P.y + s * (P.x - xR)) % self.p
        R = Point(xR, yR)
        return R

    def dbl(self, P: Point) -> Point:
        """

        :param P:
        :return:
        """
        assert isinstance(P, Point)

        # 2*0=0
        if P.x is None:
            return P

        # yP==0
        if P.y == 0:
            return [None, None]

        s = (3 * pow(P.x, 2, self.p) + self.a) * int(gmpy.invert(2 * P.y, self.p)) % self.p
        xR = (pow(s, 2, self.p) - 2 * P.x) % self.p
        yR = (-P.y + s * (P.x - xR)) % self.p
        R = Point(xR, yR)
        return R

    def mul(self, P: Point, k: int) -> Point:
        """

        :param P:
        :param k:
        :return:
        """
        assert isinstance(P, Point)
        assert isinstance(k, int)

        # x0=0
        if P.x is None:
            return P

        N = P
        R = Point(None, None)

        while k:
            bit = k % 2
            k >>= 1
            if bit:
                R = self.add(R, N)
            N = self.dbl(N)

        return R
