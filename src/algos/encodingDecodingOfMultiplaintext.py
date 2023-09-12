#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel

"""
Module for encoding and decoding of multi-plaintext
"""

import typing
import math


def encoding_message_as_multiplaintext(q: int, msg: bytearray) -> typing.List[int]:
    """
    algorithm 5: Encoding a message as a multi-plaintext

    This algorithm is not needed for the verification.

    :param q:
    :param msg:
    :return:
    """

    assert isinstance(q, int)
    assert isinstance(msg, bytearray)
    assert q > 0

    # Calc blocksize (see also decodingMessageFromMultiPlaintext(...))
    s = math.floor(math.log(q, 2) / 8)

    # Calc padding size
    k = (math.ceil((len(msg) + 2) / s) * s) - (len(msg) + 2)

    # Pad msg with 2 byte of the pad lenght k and k zero-bytes
    msgDash = bytearray()
    msgDash.extend(k.to_bytes(2, byteorder="big", signed=False))
    msgDash.extend(msg)
    msgDash.extend([0x00 for i in range(k)])

    # Walk through blocks with blocksize s
    r = []
    for i in range(0, len(msg) + 2 + k, s):
        r.append(int.from_bytes(msgDash[i:i + s], byteorder='big', signed=False))

    return r


def decoding_message_from_multiplaintext(q: int, multiplaintext: list) -> bytearray:
    """
    algorithm 6: Decoding a message from a multi-plaintext
    :param q:
    :param multiplaintext:
    :return:
    """
    assert isinstance(q, int)
    assert isinstance(multiplaintext, list)
    for m in multiplaintext:
        assert isinstance(m, int)

    # Calc blocksize (see also encodingMessageAsMultiPlaintext(...))
    s = math.floor(math.log(q, 2) / 8)

    msgDash = bytearray()
    for plaintext in multiplaintext:
        a = plaintext.to_bytes(s, byteorder="big", signed=False)
        msgDash.extend(a)

    k = int.from_bytes(msgDash[:2], byteorder="big", signed=False)

    assert int.from_bytes(msgDash[len(msgDash) - k:len(msgDash)], byteorder='big', signed=False) == 0

    msg = msgDash[2:len(msgDash) - k]

    return msg
