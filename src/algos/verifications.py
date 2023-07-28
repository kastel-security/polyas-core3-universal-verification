#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde

import typing
import math
import os
import base64
import shutil
import gnupg
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from .algorithms import uniform_hash
from .algorithms import independent_generators_for_ec_groups_of_prime_order
from .ellipticCurveEncodingDecoding import elliptic_curve_decoding
from .encodingDecodingOfMultiplaintext import decoding_message_from_multiplaintext
from .secp256k1 import secp256k1_messageUpperBound,Curve, Point, secp256k1_q
from helper.classes import *

def initialize_gpg(keys: list, path: str = "gpg_tmp"):
    """
    Initializes gnupg to perform verifications
    Parameters
    ----------
    keys : list
        List of OpenPGP keys in base64 encoding.
    path : str, optional
        Name of temorary folder the gnupg key files will be stored in.
        The default is "gpg_tmp".

    Returns
    -------
    gpg : TYPE
        DESCRIPTION.

    """
    assert isinstance(keys, list)
    if os.path.isdir(path):
        close_gpg(path = path)
    os.mkdir(path)
    gpg = gnupg.GPG(gnupghome = path)
    for publicKey in keys:
        key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + publicKey + "\n-----END PGP PUBLIC KEY BLOCK-----"
        gpg.import_keys(key)
    return gpg

def close_gpg(path: str = "gpg_tmp"):
    """
    Removes the files created by an instnce of gnupg
    Parameters
    ----------
    path : str, optional
        The path where the gnupg key files are stored. 
        The default is "gpg_tmp".

    Returns
    -------
    None.

    """
    if os.path.isdir(path):
        shutil.rmtree(path)

def verify_signature_gpg(fingerprint: str, sign: str, gpg: gnupg.GPG):
    """
    Verifies an OpenPGP signature on a revocation token fingerprint

    Parameters
    ----------
    fingerprint : str
        Fingerprint that was signed.
    sign : str
        Detached signature on the fingerprint, given in ASCII encoding.
    gpg : gnupg.GPG
        An instance of gnupg that has been initialized with the required keys.

    Returns
    -------
    boolean
        Whether the signature is valid.
    TYPE
        The fingerprint of the key used for the signature.

    """
    assert isinstance(fingerprint, str)
    assert isinstance(sign, str)
    assert isinstance(gpg, gnupg.GPG)
    with open("tmp%s.txt" % fingerprint, 'wb+') as f:
        f.write(base64.b64decode(sign))
    verified = gpg.verify_data("tmp%s.txt" % fingerprint, bytes(fingerprint, "ASCII"))
    os.remove("tmp%s.txt" % fingerprint)
    return (True if verified else False, verified.fingerprint)

def verify_signature_rsa(fingerprint: str, sign: str, key: str):
    """
    Verifies an RSA signature on a ballot fingerprint
    Parameters
    ----------
    fingerprint : str
        Fingerprint that was signed.
    sign : str
        Signature on the fingerprint in hexadecimal encoding.
    key : str
        Public key in PKCS1_v5 hexadecimal encoding.

    Returns
    -------
    bool
        Whether the signature is valid.

    """
    assert isinstance(fingerprint, str)
    assert isinstance(sign, str)
    assert isinstance(key, str)
    pubKey = RSA.importKey(bytes.fromhex(key))
    msg = SHA256.new()
    msg.update(bytes.fromhex(fingerprint))
    signBytes = bytes.fromhex(sign)
    sig = pkcs1_15.new(pubKey)
    try:
        sig.verify(msg, signBytes)
        return True
    except:
        return False


def verification_of_the_public_election_key_with_zk_proof(pk : bytearray, c : int, f : int) -> bool:
    """
    algorithm 8: Verification of the public election key with ZK proof
    :param pk:  bytearray PublicKey-ECC-Point (compressed)
    :param c:   int
    :param f:   int
    :return:    bool if the ZK-Proof is valid
    """
    assert type(pk) is bytearray
    assert type(c) is int
    assert type(f) is int

    secp256k1 = Curve()

    # Every compressed point in secp256k1 got 33bytes
    pk_point = secp256k1.decompress(pk)
    assert pk_point.valid()

    div = secp256k1.g.mul(f).add( pk_point.mul(c).inv() )
    assert div.valid()

    cDash = uniform_hash(secp256k1.q, secp256k1.g, pk, div)
    return c == cDash

def calculate_multi_plaintext_length(ballotStructures: list, publicLabel: list, q: int):
    """
    Calculate lenght of the multi-plaintext of a ballot based on the public label 
    Parameters
    ----------
    ballotStructures : list
        A map from public label to respective ballot sheet
    publicLabel : list
        A list of ballot sheet ids extracted from the public label.

    Returns
    -------
    None.

    """
    byteCount = 0
    for ballotSheet in publicLabel:
        assert isinstance(ballotSheet, str)
        # 1 byte marks the ballot sheet as valid or invalid
        byteCount += 1
        ballotStructure = ballotStructures[ballotSheet]
        assert isinstance(ballotStructure, Core3Ballot)
        for candidateList in ballotStructure.lists:
            # 1 byte contains the total number of votes for a list
            byteCount += 1
            assert isinstance(candidateList, CandidateList)
            # 1 byte for each candidate
            for candidate in candidateList.candidates:
                if candidate.writeInSize > 0:
                    byteCount += candidate.writeInSize
                else:
                    byteCount += 1

    # Calc blocksize of multiplaintext
    # Round result first to avoid errors due to arithmetic errors
    s = math.floor(round(math.log(q,2)/8, 8))

    # Calculate length of teh multiplaintext
    return math.ceil(round((byteCount + 2) / s, 8))



def verification_of_a_ballot_entry_extended(registry: Registry, ballot: BallotBoxEntry, prevBallots: list, pk: bytearray()):
    """
    Verification task for a single BallotBoxEntry in BallotBox

    Parameters
    ----------
    registry : Registry
        The registry of the election.
    ballot : BallotBoxEntry
        The ballot box entry to be verified.
    prevBallots : list
        Map of public credentials of ballot to ballot that were previously checked

    Returns
    -------
    bool
        True if ballot is valid and not a duplicate.

    """
    # Calculate map of ballot structures identified by id
    ballotStructures = {}
    for ballotStructure in registry.ballotStructures:
        ballotStructures[ballotStructure.id] = ballotStructure
    # Step 1: Voter to ballot exists
    voter = None
    for t in registry.voters:
        if t.cred == ballot.publicCredential:
            voter = t
            break

    if voter == None:
        return False

    # Step 2: Public label is correct
    if voter.publicLabel != ballot.publicLabel:
        return False

    # Step 2.1 All Public Labels are valid, not explicitly mentioned in Polyas 3.0
    ballotSheets = ballot.publicLabel.split(":")
    for ballotSheet in ballotSheets:
        if not isinstance(ballotStructures[ballotSheet], Core3Ballot):
            return False

    # Step 3: Check length of multi-ciphertext (should be teh same as length of multi-plaintext)
    expected_length = calculate_multi_plaintext_length(ballotStructures, ballotSheets, secp256k1_q)
    if expected_length != len(ballot.ballot.encryptedChoice.ciphertexts):
        #print(expected_length, len(ballot.ballot.encryptedChoice.ciphertexts))
        return False

    # Step 4: No ballot with the same voters credentials
    if ballot.publicCredential in prevBallots:
        return False

    l = ballot.publicLabel
    z = ballot.publicCredential
    encryptedChoices = [x.tup for x in ballot.ballot.encryptedChoice.ciphertexts]
    privateCredentials = ballot.ballot.proofOfKnowledgeOfPrivateCredential.tup
    encryptedCoins = [x.tup for x in ballot.ballot.proofOfKnowledgeOfEncryptionCoins]

    # Step 5: Check actual proofs of ballot
    return verification_of_a_ballot_entry(pk, l, z, encryptedChoices, privateCredentials, encryptedCoins)


def verification_of_a_ballot_entry(pk : bytearray, l : str, z : bytearray, encrypted_choices : typing.List, private_credentials : tuple, encrypted_coins : typing.List) -> bool:
    """
    Algorithm 9: Verification of a ballot entry
    :param pk:              bytearray PublicKey-ECC-Point (compressed)
    :param l:               str
    :param z:               bytearray
    :param choices:         List
    :param credentialProof: tuple
    :param encryptionProof: List
    :return:                bool. True if the BallotEntry is verified correct
    """
    assert isinstance(pk, bytearray)
    assert isinstance(l, str)
    assert isinstance(z, bytearray)

    for ei in encrypted_choices:
        assert type(ei) is tuple
        (xi, yi) = ei
        assert type(xi) is bytearray
        assert type(yi) is bytearray

    assert type(private_credentials) is tuple
    (c,f) = private_credentials
    assert type(c) is int
    assert type(f) is int

    for cfi in encrypted_coins:
        assert type(cfi) is tuple
        (ci,fi) = cfi
        assert type(ci) is int
        assert type(fi) is int

    # TODO Check that all (sub) components of the input are in the expected domains

    secp256k1 = Curve()

    # Check if pk is valid
    assert secp256k1.decompress(pk).valid()

    z_point = secp256k1.decompress(z)
    assert z_point.valid()

    (c,f) = private_credentials

    div = secp256k1.g.mul(f).add( z_point.mul(c).inv() )
    assert div.valid()

    encryp = []
    for e in encrypted_choices:
        (x,y) = e
        assert secp256k1.decompress(x).valid()
        assert secp256k1.decompress(y).valid()
        encryp.append(x)
        encryp.append(y)

    cDash = uniform_hash(secp256k1.q, secp256k1.g, pk, l, *encryp, z, div)

    if cDash != c:
        return False

    return True

def verification_of_a_zk_proof_of_shuffle(pk : bytearray, input_es : list, output_es : list, zkproof : tuple, test=False, progressbar=None) -> bool:
    """
    Algorithm 12: Verification of a ZK-Proof of Shuffle
    :param pk:          bytearray PublicKey-ECC-Point (compressed)
    :param input_es:    List
    :param output_es:   List
    :param zkproof:     tuple of the proof: (c,cHat,t1,t2,t3,t4,tHat,s1,s2,s3,s4,sHat,sPrime)
    :param test:        This parameter is only used for the unittests, as we have got some steps inbetween to check. I cannt breakof the function as all of those algorithms are directly give by a document and should stay consistent to it.
    :param progressbar: You could handle a progessbar object here to be updated by the progress of the verification
    :return:            bool, True if the verification was correct
    """

    assert type(pk) is bytearray
    assert type(input_es) is list
    for ej in input_es:
        assert type(ej) is list
        for ei in ej:
            assert type(ei) is tuple
            (xi, yi) = ei
            assert type(xi) is bytearray
            assert type(yi) is bytearray

    assert type(output_es) is list
    for ej in output_es:
        assert type(ej) is list
        for ei in ej:
            assert type(ei) is tuple
            (xi, yi) = ei
            assert type(xi) is bytearray
            assert type(yi) is bytearray

    N = len(input_es)
    w = len(input_es[0])

    assert len(input_es) == N
    assert len(output_es) == N

    assert len(input_es[0]) == w
    assert len(output_es[0]) == w

    assert type(zkproof) is tuple

    # Parsing ZK-Proof
    (c,cHat,t1,t2,t3,t4,tHat,s1,s2,s3,s4,sHat,sPrime) = zkproof

    assert type(c) is list
    for ci in c:
        assert type(ci) is bytearray

    assert len(c) == N

    assert type(cHat) is list
    for cHati in c:
        assert type(cHati) is bytearray

    assert len(cHat) == N

    assert type(t1) is bytearray
    assert type(t2) is bytearray
    assert type(t3) is bytearray

    assert type(t4) is list
    for t4i in t4:
        assert type(t4i) is tuple
        (xi, yi) = t4i
        assert type(xi) is bytearray
        assert type(yi) is bytearray

    assert len(t4) == w

    assert type(tHat) is list
    for tHati in tHat:
        assert type(tHati) is bytearray

    assert len(tHat) == N

    assert type(s1) is int
    assert type(s2) is int
    assert type(s3) is int

    assert type(s4) is list
    for s4i in s4:
        assert type(s4i) is int

    assert len(s4) == w

    assert type(sHat) is list
    for sHati in sHat:
        assert type(sHati) is int

    assert len(sHat) == N

    assert type(sPrime) is list
    for sPrimei in sPrime:
        assert type(sPrimei) is int

    assert len(sPrime) == N


    # Step 1
    N = len(input_es)
    w = len(input_es[0])

    curve = Curve()

    # Build h, and hs. This is done outside of this function in the documentation but you could also (better) do it inside
    h = independent_generators_for_ec_groups_of_prime_order(curve.p, curve.a, curve.b, bytearray("Polyas".encode("utf-8")), 10).compress_as_bytearray()

    hs = []
    for i in range(N):
        hs.append(independent_generators_for_ec_groups_of_prime_order(curve.p, curve.a, curve.b, bytearray("Polyas".encode("utf-8")), 10 + i + 1).compress_as_bytearray())

    # Bringing the inputCiphertexts in the right format
    # seems to be unneccessary
    es = []
    for ej in input_es:
        for ei in ej:
            (xi, yi) = ei
            es.append(xi)
            es.append(yi)

    eDashs = []
    for ej in output_es:
        for ei in ej:
            (xi, yi) = ei
            eDashs.append(xi)
            eDashs.append(yi)

    t4s = []
    for t4i in t4:
        (xi, yi) = t4i
        t4s.append(xi)
        t4s.append(yi)
    us = []
    for i in range(1,N+1):
        ui = uniform_hash(curve.q, curve.g.compress_as_bytearray(), pk, h, *hs, *input_es, *output_es, *c, i)
        #ui = uniform_hash(curve.q, curve.g.compress_as_bytearray(), pk, h, *hs, *es, *eDashs, *c, i)
        us.append(ui)

    # Run this part only for the unittests!
    if test == True:
        assert us[0] == 25423173261403838045780498659101929143374212024885961749677191123894345457203
        assert us[1] == 107163395173780552120959839682734915419294108435315434884329493449297702516989
        assert us[2] == 27527278399601879823598941265103560004203827776425685772980663219237052390097
        assert us[3] == 106382107453541024383519774022048119452768386444341851381719160092926187339847
        assert us[4] == 78025421855638301792439005550141533632218318123084187717794732643161239341502

    # Step 2
    #challenge = uniform_hash(curve.q, curve.g.compress_as_bytearray(), pk, h, *hs, *es, *eDashs, *c, cHat, t1, t2, t3, t4s, tHat)
    challenge = uniform_hash(curve.q, curve.g.compress_as_bytearray(), pk, h, *hs, *es, *eDashs, *c, cHat, t1, t2, t3, t4, tHat)

    if test == True:
        assert challenge == 14886957920142020425415970750713297044432709962075734803391029210025459699280

    # Step 3 (Step 5 of Algorithm 10)

    ## Checking t1
    t1tmp1 = curve.decompress(c[0])
    t1tmp2 = curve.decompress(hs[0])
    for i in range(1,N):
        t1tmp1 = t1tmp1.add(curve.decompress(c[i]))
        t1tmp2 = t1tmp2.add(curve.decompress(hs[i]))

    t1tmp3 = t1tmp1.add(t1tmp2.inv())

    # Calculate the additive inverse
    negChallenge = curve.q - challenge

    t1tmp3 = t1tmp3.mul(negChallenge)

    t1tmp4 = curve.decompress(h).mul(s1)

    t1tmp5 = t1tmp3.add(t1tmp4)

    if t1tmp5.compress_as_bytearray() != t1:
        return False

    if progressbar != None:
        progressbar.setValue(20)

    ## Checking t2
    t2tmp1 = us[0]
    for i in range(1,N):
        t2tmp1 = t2tmp1 * us[i]

    t2tmp2 = curve.decompress(hs[0]).mul( t2tmp1 )
    t2tmp3 = curve.decompress(cHat[N-1]).add( t2tmp2.inv())
    t2tmp4 = t2tmp3.mul(negChallenge)

    t2tmp5 = t2tmp4.add( curve.decompress(h).mul(s2) )
    if t2tmp5.compress_as_bytearray() != t2:
        return False

    if progressbar != None:
        progressbar.setValue(40)

    ## Checking t3
    t3tmp1 = curve.decompress(c[0]).mul(us[0])
    t3tmp2 = curve.decompress(hs[0]).mul(sPrime[0])
    for i in range(1,N):
        t3tmp1 = t3tmp1.add(curve.decompress(c[i]).mul(us[i]))
        t3tmp2 = t3tmp2.add(curve.decompress(hs[i]).mul(sPrime[i]))

    t3tmp3 = t3tmp1.mul(negChallenge)
    t3tmp3 = t3tmp3.add(curve.decompress(h).mul(s3))

    t3tmp4 = t3tmp3.add(t3tmp2)

    if t3tmp4.compress_as_bytearray() != t3:
        return False

    if progressbar != None:
        progressbar.setValue(60)

    ## Checking t4
    for j in range(0,w):
        t4tmp1x = curve.decompress(input_es[0][j][0]).mul(us[0])
        t4tmp1y = curve.decompress(input_es[0][j][1]).mul(us[0])
        t4tmp2x = curve.decompress(output_es[0][j][0]).mul(sPrime[0])
        t4tmp2y = curve.decompress(output_es[0][j][1]).mul(sPrime[0])
        for i in range(1,N):
            t4tmp1x = t4tmp1x.add(curve.decompress(input_es[i][j][0]).mul(us[i]))
            t4tmp1y = t4tmp1y.add(curve.decompress(input_es[i][j][1]).mul(us[i]))
            t4tmp2x = t4tmp2x.add(curve.decompress(output_es[i][j][0]).mul(sPrime[i]))
            t4tmp2y = t4tmp2y.add(curve.decompress(output_es[i][j][1]).mul(sPrime[i]))

        t4tmp3x = t4tmp1x.mul(negChallenge)
        t4tmp3y = t4tmp1y.mul(negChallenge)
        t4tmp4x = t4tmp3x.add(t4tmp2x)
        t4tmp4y = t4tmp3y.add(t4tmp2y)

        negS4 = curve.q - s4[j]
        (t4tmp5x, t4tmp5y) = ReEnc(curve.g, curve.decompress(pk), (t4tmp4x, t4tmp4y), negS4)
        (t4x, t4y) = t4[j]
        if t4x != t4tmp5x.compress_as_bytearray() or t4y != t4tmp5y.compress_as_bytearray():
            return False

        if progressbar != None:
            progressbar.setValue(80)

    ## Checking tHat
    for i in range(0,N):
        tHatTmp1 = curve.decompress(cHat[i]).mul(negChallenge)
        tHatTmp2 = curve.decompress(h).mul(sHat[i])
        if i == 0:
            tHatTmp3 = curve.decompress(hs[0]).mul(sPrime[i])
        else:
            tHatTmp3 = curve.decompress(cHat[i - 1]).mul(sPrime[i])
        tHatTmp4 = tHatTmp1.add(tHatTmp2)
        tHatTmp4 = tHatTmp4.add(tHatTmp3)
        if tHatTmp4.compress_as_bytearray() != tHat[i]:
            return False

    return True

def ReEnc(g : Point, pk : Point, e : list, r : int) -> tuple:
    """
    ReEnc Helpfunction for algorithms 10 - 12
    This is only implements the part for single points not for lists!
    :param g:   Point
    :param pk:  Point, PublicKey-ECC-Point
    :param e:   List
    :param r:   int
    :return:    tuple
    """

    assert type(g) is Point
    assert type(pk) is Point
    assert type(e) is tuple
    assert len(e) == 2
    for ei in e:
        assert type(ei) is Point
    assert type(r) is int

    return ( e[0].add(g.mul(r)), e[1].add(pk.mul(r)) )



def verification_of_ballot_decrytion(pk : bytearray, ciphertexts : list, message : bytearray, proofs : list) -> bool:
    """
    algorithm 13: Verification of ballot decryption
    :param pk:          bytearray of PublicKey-ECC-Point (compressed)
    :param ciphertexts: List
    :param message:     bytearray
    :param proofs:      List
    :return:            bool, True if verification is valid
    """
    assert type(pk) is bytearray

    assert type(ciphertexts) is list
    for ei in ciphertexts:
        assert type(ei) is tuple
        (xi, yi) = ei
        assert type(xi) is bytearray
        assert type(yi) is bytearray

    assert type(message) is bytearray

    assert type(proofs) is list
    for proofi in proofs:
        assert type(proofi[0]) is bytearray #  alpha / decryptionShare
        assert type(proofi[1]) is tuple # Pi / eqlogZKP
        assert type(proofi[1][0]) is int # c
        assert type(proofi[1][1]) is int # f


    curve = Curve()
    pk = curve.decompress(pk)
    dis = []

    # Step 1: Check domains
    # TODO

    # Step 2
    for i in range(0, len(ciphertexts)):
        proofi = proofs[i]
        alphai = curve.decompress(proofi[0])
        ci = proofi[1][0]
        fi = proofi[1][1]

        xi = curve.decompress(ciphertexts[i][0])
        yi = curve.decompress(ciphertexts[i][1])


        # Step 3
        Ai = curve.g.mul(fi).add(  pk.mul(ci).inv() )

        Bi = xi.mul(fi).add( alphai.mul(ci).inv() )

        # Step 4
        cDashi = uniform_hash(curve.q, curve.g, xi, pk, alphai, Ai, Bi)

        # Step 5
        if cDashi != ci:
            return False

        # Step 6
        di = elliptic_curve_decoding(yi.add(alphai.inv()))
        dis.append(di)

    # Step 7
    # TODO dont use secp256k1 as str in the code!
    m = decoding_message_from_multiplaintext(secp256k1_messageUpperBound, dis)
    if m != message:
        return False

    return True

def byte_reader(b):
    """
    Helperfunction: yields a bytearray byte-by-byte
    """
    for i in b:
        yield i

def decoding_of_a_decrypted_ballot(content : bytearray) -> list:
    """
    algorithm 14: decoding of a decrypted ballot

    This algorithm is no longer needed from > v0.9.0

    The message format hat changed.


    DEPRECATED

    :param content:
    :return:
    """

    assert type(content) is bytearray

    res = []

    reader = byte_reader(content)
    m = next(reader)
    for i in range(0,m):
        sheeti = []
        b = next(reader)
        fi = (b & (1 << 7)) == 0x80
        sidi = b & (0x7F)

        sheeti.append(sidi)
        sheeti.append(fi)
        ni = next(reader)
        for j in range(0,ni):
            idij = next(reader)
            vij = next(reader)
            sheeti.append( (vij, idij) )
            assert vij & ( 1 << 7) == 0
        # Don't read these byte for productionsetup
        #next(reader)
        #next(reader)
        res.append(sheeti)
    return res
