#!/bin/python
# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde

import hashlib
import hmac
import typing

import math

from .TonelliShanks import tonelli
from .secp256k1 import Point, Curve, secp256k1_q

def kdf(l: int, k: bytearray, label: bytearray, context: bytearray) -> bytearray:
    """
    algorithm 1: Key Derivation Function

    Creates a pseudo-random byte array from a given seed k with a given length l

    :param l:
    :param k:
    :param label:
    :param context:
    :return:
    """
    assert isinstance(l, int)
    assert isinstance(k, bytearray)
    assert isinstance(label, bytearray)
    assert isinstance(context, bytearray)


    # Blocks as array
    B = []

    # The resulting bytearray
    result = bytearray()

    # Build as many blocks as needed
    for i in range(0, int(l / 64) + 1):
        # Build up payload array
        paybytes = bytearray()
        paybytes.extend(i.to_bytes(4, byteorder='big'))
        paybytes.extend(label)
        paybytes.append(0x00)
        paybytes.extend(context)
        paybytes.extend(int(l).to_bytes(4, byteorder='big'))

        B.append(bytearray.fromhex(hmac.new(k, paybytes, hashlib.sha512).hexdigest()))

    # Get l bytes from the 64byte-blocks
    for i in range(0, l):
        tmp = int(i / 64)
        result.append(B[tmp][i - (tmp * 64)])

    return result

def numbers_from_seed(l: int, seed: bytearray) -> bytearray:
    """
    algorithm 2: Numbers from seed

    :param l:
    :param seed:
    :return:
    """

    assert isinstance(l, int)
    assert isinstance(seed, bytearray)


    i = 1
    while True:
        k = bytearray(seed)
        k.extend(i.to_bytes(4, byteorder='big'))

        b = kdf(math.ceil(l / 8), k, bytearray("generator".encode("utf-8")), bytearray("Polyas".encode("utf-8")))

        # Set bits that are to much to zero
        for bit in range(0, -l % 8):
            b[0] = b[0] & ~(1<<7-bit)

        yield (int.from_bytes(b, byteorder='big', signed=False))
        i = i+1

def numbers_from_seed_range(b: int, seed: bytearray) -> typing.List[int]:
    """
    algorithm 3: Numbers from seed (range)

    :param b:
    :param seed:
    :return:
    """
    assert isinstance(b, int)
    assert isinstance(seed, bytearray)

    gen = numbers_from_seed(math.ceil(math.log(b, 2)), seed)

    for i in gen:
        if 0 <= i < b:
            yield i

def bytes_needed( n : int) -> int:
    """
    Helper function for algorithm 4 (uniform hash) to get the length in bytes. This function is NOT unittested.
    :param n:
    :return:
    """
    assert isinstance(n, int)

    if n == 0:
        return 1
    return int(math.log(n, 256)) + 1


def build_bytearray_by_type(input) -> bytearray:
    """
    Helper function for algorithm 4 (uniform hash) to build a bytearray from different input-types. This function is unittested.
    :param input:
    :return:
    """
    r = bytearray()
    if isinstance(input, str):
        r.extend(input.encode("utf-8"))
    elif isinstance(input, int):
        b = bytes_needed(input)
        if b <= 4:
            r.extend(input.to_bytes(4, byteorder='big'))
        else:
            r.extend(b.to_bytes(4, byteorder='big'))
            r.extend(input.to_bytes(b, byteorder='big'))
    elif isinstance(input, bytearray):
        r.extend(input)
    elif isinstance(input, list):
        for arg in input:
            r.extend(build_bytearray_by_type(arg))
    elif isinstance(input, tuple):
        input1, input2 = input
        if isinstance(input1, int) and isinstance(input2, int):
            r.extend(build_bytearray_by_type(input1))
            r.extend(build_bytearray_by_type(input2))
        elif isinstance(input1, bytearray) and isinstance(input2, bytearray):
            r.extend(build_bytearray_by_type(input1))
            r.extend(build_bytearray_by_type(input2))
        else:
            raise Exception("No valid inputtype. {type(input)} is not ok.")
    elif isinstance(input, Point):
        r.extend(input.compress_as_bytearray())
    else:
        raise Exception("No valid inputtype. {type(input)} is not ok.")

    return r


def revocation_token_fingerprint(q: int, token: str) -> str:
    """

    :param q:
    :param args:
    :return:
    """
    assert isinstance(q, int)
    assert isinstance(token, str)

    inputdata = build_bytearray_by_type(token)

    # Run SHA256 hash over the concated bytearrays
    return hashlib.sha256(inputdata).hexdigest()[0:20]

def uniform_hash(q: int, *args) -> int:
    """
    algorithm 4: Uniform hash

    :param q:
    :param args:
    :return:
    """
    inputdata = bytearray()

    # Build bytearray for every argument and concat them
    for i in args:
        tmp = build_bytearray_by_type(i)
        inputdata.extend(tmp)
    # Run SHA512 hash over the concated bytearrays
    h = bytearray.fromhex(hashlib.sha512(inputdata).hexdigest())

    gen = numbers_from_seed_range(q, h)
    for r in gen:
        return r

def independent_generators_for_ec_groups_of_prime_order(p: int, a: int, b: int, seed: bytearray, index: int) -> int:
    """
    algorithm 7: Independent generators for EC groups of prime order
    :param p:
    :param a:
    :param b:
    :param seed:
    :param index:
    :return:
    """
    assert isinstance(p, int)
    assert isinstance(a, int)
    assert isinstance(b, int)
    assert isinstance(seed, bytearray)
    assert isinstance(index, int)

    curve = Curve()

    s = bytearray()
    s.extend(seed)
    s.extend(bytearray("ggen".encode("utf-8")))
    s.extend(index.to_bytes(4, byteorder="big", signed=False))
    # Calling algorithm 3
    ws = numbers_from_seed_range(2 * curve.p, s)

    for w in ws:
        x = w % p
        try:
            yDash = tonelli( (pow(x,3) + (a * x) + b)%p, p)
        except:
            continue

        if w < p:
            y = (-yDash % p)
        else:
            y = yDash
        # TODO check for infinity!
        return Point(x,y)
