#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel

"""
Module for encoding and decoding of numbers to elliptic curve points
"""
import typing
import math


# Local imports
from .TonelliShanks import tonelli

from .secp256k1 import secp256k1_p, secp256k1_a, secp256k1_b, secp256k1_k, Point


def elliptic_curve_encoding(a: int) -> typing.Tuple[int, int]:
    """
    Helperfunction: Encoding a message a to a point on the curve. May fail with a given probability.
    :param a:
    :return:
    """
    assert isinstance(a, int)
    for i in range(1, secp256k1_k + 1):
        x = (a * secp256k1_k + i) % secp256k1_p

        # Solve elliptic curve equation (Tonelli-Shanks Algorithm)
        y = tonelli((pow(x, 3) + (secp256k1_a * x) + secp256k1_b) % secp256k1_p, secp256k1_p)

        if y != 0:
            return (x, y)

    raise ValueError("Found no point on the curve! See v0.9.pdf page 22")


def elliptic_curve_decoding(pt: Point) -> int:
    """
    Helperfunction: Decoding point on the curve back to the message a
    :param x:
    :param y:
    :return:
    """
    assert isinstance(pt, Point)

    return math.floor((pt.x-1)//secp256k1_k)
