#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde

import logging
import PyPDF2
import argparse
import hashlib
import json
import os
import re
import math
from algos.secp256k1 import secp256k1_q as q

from helper.classes import BallotBoxEntry, BallotStatus, AnnotatedBallot, RevocationToken, RevocationTokenAuthorisation, MessageWithProofPacket, PublicKeyWithZKP, MixPacket, Registry, ReceiptStatus
from helper.secureJSON import loadSecureJSON

from algos.verifications import initialize_gpg, verify_signature_gpg, close_gpg, verification_of_a_ballot_entry_extended, verification_of_a_zk_proof_of_shuffle
from algos.verifications import verification_of_the_public_election_key_with_zk_proof, verification_of_ballot_decrytion, verify_signature_rsa, byte_reader
from algos.algorithms import revocation_token_fingerprint, build_bytearray_by_type

VERSION_MAJOR = 1
VERSION_MINOR = 2
VERSION_PATCH = 0
VERSION = "v" + str(VERSION_MAJOR) + "." + str(VERSION_MINOR) + "." + str(VERSION_PATCH)


logger = logging.getLogger("polyas_checker.py")
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)

logger.addHandler(ch)


greenStyle = """
QProgressBar {
    border: 2px solid grey;
    border-radius: 5px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: lightgreen;
}
"""


redStyle = """
QProgressBar {
    border: 2px solid grey;
    border-radius: 5px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #f96a6a;
}
"""


def load_ballot_box(path):
    ballotBoxJSON = loadSecureJSON(path, "ballot-box.json")
    ballotBox = []
    for bbp in ballotBoxJSON:
        for bb in bbp["ballots"]:
            ballotBox.append(BallotBoxEntry(bb))
    return ballotBox


def count_signatures(registry, authCount):
    """
    List the fingerprints of keys used for valid authorisations for each provided
    token
    Parameters
    ----------
    path : str
        path to election board files
    registry : Registry
        registry board of the election.
    tokens : map
        A map of revokation tokens to a list.

    Returns
    -------
    None.

    """
    gpg = initialize_gpg(registry.revocationPolicy.verificationKeys)
    authorisations = load_revocation_authorisation(path)
    for auth in authorisations:
        verification = verify_signature_gpg(auth.tokenFingerprint, auth.signature, gpg)
        if verification[0] and auth.tokenFingerprint in authCount:
            if not verification[1] in authCount[auth.tokenFingerprint]:
                authCount[auth.tokenFingerprint].append(verification[1])


def collect_valid_revocations(path, registry):
    """
    Collects voterIds of all validly revoked ballots

    Parameters
    ----------
    path : str
        path to election board files.
    registry : TYPE
        registry board of the election.

    Returns
    -------
    list
        List of voterIds of revoked ballots.

    """
    if (registry.revocationPolicy is None):
        return []
    tokens = load_revocation_tokens(path)
    authCount = {}
    for token in tokens:
        if token.electionId == registry.electionId:
            fingerprint = revocation_token_fingerprint(q, token.normalized())
            authCount[fingerprint] = []
        else:
            tokens.remove(token)
    if (registry.revocationPolicy.threshold > 0):
        count_signatures(registry, authCount)
    authorised = []
    for token in tokens:
        fingerprint = revocation_token_fingerprint(q, token.normalized())
        if len(authCount[fingerprint]) >= registry.revocationPolicy.threshold:
            for voterId in token.voterIds:
                if voterId not in authorised:
                    authorised += [voterId]
    if (registry.revocationPolicy.threshold > 0):
        close_gpg()
    return authorised


def verify_ballot_box(path, progressbar=None):
    ballotBox = load_ballot_box(path)
    ballotBoxFlagged = load_ballot_box_flagged(path)
    registry = load_registry(path)
    assert len(ballotBox) == len(ballotBoxFlagged)

    keyGenElectionKey = load_key_gen_election_key(path)
    pk = keyGenElectionKey.publicKey
    revocations = collect_valid_revocations(path, registry)

    pastCredentials = []
    for i in range(len(ballotBox)):
        bb = ballotBox[i]
        bba = ballotBoxFlagged[i]
        if not bba.ballot.__eq__(bb):
            progressbar.setValue(int((i + 1) * 100 / len(ballotBox))) if progressbar is not None else None
            logger.info("The ballot of voter %s is incorrectly transferred from the ballot box to ballot-box-flagged." % bb.voterID)
            return False
        flag = ""
        if not verification_of_a_ballot_entry_extended(registry, bb, pastCredentials, pk):
            flag = BallotStatus.INCORRECT
        elif bb.voterID in revocations:
            flag = BallotStatus.REVOKED
        else:
            flag = BallotStatus.OK
        pastCredentials += [bb.publicCredential]
        if flag != bba.status:
            logger.info("The ballot of voter %s is incorrectly flagged: Expected %s but was %s." % (bb.voterID, flag, bba.status))
            return False

        if progressbar is not None:
            progressbar.setValue(int((i + 1) * 100 / len(ballotBox)))

    if progressbar is not None:
        progressbar.setValue(100)
    return True


def load_ballot_box_flagged(path):
    ballotFlaggedJSON = loadSecureJSON(path, "ballot-flagged.json")
    ballotBox = []
    for bbp in ballotFlaggedJSON:
        for bb in bbp["values"]:
            ballotBox.append(AnnotatedBallot(bb))
    return ballotBox


def load_revocation_tokens(path):
    revocationTokensJSON = loadSecureJSON(path, "revocations.json")
    tokens = []
    for token in revocationTokensJSON:
        tokens.append(RevocationToken(token))
    return tokens


def load_revocation_authorisation(path):
    revokationAuthorisationJSON = loadSecureJSON(path, "revocation-authorisations.json")
    authorisations = []
    for authorisation in revokationAuthorisationJSON:
        authorisations.append(RevocationTokenAuthorisation(authorisation))
    return authorisations


def load_ballot_box_filtered_out(path):
    ballotFlaggedJSON = loadSecureJSON(path, "ballot-filtered-out.json")
    ballotBox = []
    for bb in ballotFlaggedJSON:
        ballotBox.append(AnnotatedBallot(bb))
    return ballotBox


def load_decryption_decrypt(path):
    messagePacketsJSON = loadSecureJSON(path, "decryption-decrypt-Polyas.json")
    messagePackets = []
    for m in messagePacketsJSON:
        messagePackets.append(MessageWithProofPacket(m))
    return messagePackets


def load_key_gen_election_key(path):
    keyGenElectionKeyJSON = loadSecureJSON(path, "keygen-electionKey-Polyas.json", sequence=False)
    return PublicKeyWithZKP(keyGenElectionKeyJSON)


def load_mixing_mix(path):
    mixPacketsJSON = loadSecureJSON(path, "mixing-mix-Polyas.json")
    mixPackets = []
    for mp in mixPacketsJSON:
        mixPackets.append(MixPacket(mp))
    return mixPackets


def load_mixing_input_packets(path):
    mixPacketsJSON = loadSecureJSON(path, "mixing-input-packets.json")
    mixPackets = []
    for mp in mixPacketsJSON:
        mixPackets.append(MixPacket(mp))
    return mixPackets


def verify_mixing_input(path, progressbar=None):
    inputMixPackets = load_mixing_input_packets(path)
    flaggedBallots = load_ballot_box_flagged(path)
    registry = load_registry(path)
    # Grouping mixing packets by their public label
    packetsByLabel = {}  # Position of all packets fwith a given public label in inputMixPackets
    packetCountByLabel = {}  # Position the first packet that has not been fully analysed in the corresponding list in packetsByLabel
    packetPosByLabel = {}  # Position of the first ballot that has not been analysed in the current package
    for t in range(len(inputMixPackets)):
        packet = inputMixPackets[t]
        if packet.publicLabel not in packetsByLabel:
            packetsByLabel[packet.publicLabel] = []
            packetCountByLabel[packet.publicLabel] = 0
            packetPosByLabel[packet.publicLabel] = 0
        packetsByLabel[packet.publicLabel].append(t)

    # Check that all packets have the correct size
    for publicLabel in packetsByLabel:
        packetsOfLabel = packetsByLabel[publicLabel]
        if len(packetsOfLabel) == 1 and len(packetsOfLabel) <= registry.packetSize:
            # We want each packets to contain at least one packet and each packet to contain at least one ballot
            if len(inputMixPackets[packetsOfLabel[0]].ciphertexts) == 0:
                packetsByLabel.pop(publicLabel)
            continue
        for packet in packetsOfLabel:
            if len(inputMixPackets[packet].ciphertexts) > registry.packetSize or len(inputMixPackets[packet].ciphertexts) < registry.packetSize / 2:
                if progressbar is not None:
                    progressbar.setValue(100)
                logger.info("A packet on the board mixing-input-packets for public label %s has an invalid size." % publicLabel)
                return False

    # Check that all valid ballots are transferred to the mixing packets
    for t in range(0, len(flaggedBallots)):
        expectedBallot = flaggedBallots[t].ballot
        if flaggedBallots[t].status != BallotStatus.OK:
            continue
        label = expectedBallot.publicLabel
        if label not in packetsByLabel:
            if progressbar is not None:
                progressbar.setValue(100)
            logger.info("The board mixing-input-packets misses the ballot of voter %s." % expectedBallot.voterID)
            return False
        correspondingPacket = inputMixPackets[packetsByLabel[label][packetCountByLabel[label]]]
        if not expectedBallot.ballot.encryptedChoice.__eq__(correspondingPacket.ciphertexts[packetPosByLabel[label]]):
            if progressbar is not None:
                progressbar.setValue(100)
            logger.info("The board mixing-input-packets misses the ballot of voter %s." % expectedBallot.voterID)
            return False
        packetPosByLabel[label] += 1
        if packetPosByLabel[label] >= len(correspondingPacket.ciphertexts):
            packetPosByLabel[label] = 0
            packetCountByLabel[label] += 1
            # The last ballot with this public label in the mixing packets
            if packetCountByLabel[label] >= len(packetsByLabel[label]):
                packetsByLabel.pop(label)
                packetCountByLabel.pop(label)
                packetPosByLabel.pop(label)

        if progressbar is not None:
            progressbar.setValue(int((t + 1) * 100 / len(flaggedBallots)))

    # Check that no ballots were added to the mixing packets
    if len(packetsByLabel) > 0:
        if progressbar is not None:
            progressbar.setValue(100)
        logger.info("The board mixing-input-packets contains additional ballots.")
        return False
    return True


def verify_shuffle(path, progressbar=None):
    keyGenElectionKey = load_key_gen_election_key(path)
    pk = keyGenElectionKey.publicKey

    mixPackets = load_mixing_mix(path)
    inputMixPackets = load_mixing_input_packets(path)

    if len(mixPackets) != len(inputMixPackets):
        if progressbar is not None:
            progressbar.setValue(100)
        logger.info("The number of the packets before and after the mixing differ.")
        return False

    for i in range(len(mixPackets)):
        mixPacket = mixPackets[i]
        inputMixPacket = inputMixPackets[i]
        inCipher = [[x.tup for x in multicipher.ciphertexts] for multicipher in inputMixPacket.ciphertexts]
        outCipher = [[x.tup for x in multicipher.ciphertexts] for multicipher in mixPacket.ciphertexts]

        zkproof = (
            mixPacket.proof.c,
            mixPacket.proof.cHat,
            mixPacket.proof.t.t1,
            mixPacket.proof.t.t2,
            mixPacket.proof.t.t3,
            mixPacket.proof.t.t4,
            mixPacket.proof.t.tHat,
            mixPacket.proof.s.s1,
            mixPacket.proof.s.s2,
            mixPacket.proof.s.s3,
            mixPacket.proof.s.s4,
            mixPacket.proof.s.sHat,
            mixPacket.proof.s.sPrime,
        )

        if verification_of_a_zk_proof_of_shuffle(pk, inCipher, outCipher, zkproof, progressbar=progressbar) is not True:
            if progressbar is not None:
                progressbar.setValue(100)
            return False

        if progressbar is not None:
            progressbar.setValue(int((i + 1) * 100 / len(mixPackets)))

    if progressbar is not None:
        progressbar.setValue(100)
    return True


def verify_public_election_key(path, progressbar=None):
    keyGenElectionKey = load_key_gen_election_key(path)
    pk = keyGenElectionKey.publicKey
    c = keyGenElectionKey.zkp.c
    f = keyGenElectionKey.zkp.f
    if progressbar is not None:
        progressbar.setValue(100)
    return verification_of_the_public_election_key_with_zk_proof(pk, c, f)


def verify_ballot_decryption(path, progressbar=None):
    keyGenElectionKey = load_key_gen_election_key(path)
    pk = keyGenElectionKey.publicKey

    messages = load_decryption_decrypt(path)
    mixMixingPackets = load_mixing_mix(path)

    if (len(messages) != len(mixMixingPackets)):
        if progressbar is not None:
            progressbar.setValue(100)
        logger.info("The number of the decrypted packets differs from the number of mixing packets.")
        return False

    for i in range(len(messages)):
        if (len(messages[i].messagesWithZKP) != len(mixMixingPackets[i].ciphertexts)):
            if progressbar is not None:
                progressbar.setValue(100)
            logger.info("The number of decrypted messages in a packet differs from the number of encrypted messages in the corresponding mixing packet.")
            return False
        for j in range(len(mixMixingPackets[i].ciphertexts)):
            messagesWithZKP = messages[i].messagesWithZKP[j]
            multiciphertexts = mixMixingPackets[i].ciphertexts[j]

            ciphertexts = [x.tup for x in multiciphertexts.ciphertexts]
            message = messagesWithZKP.message
            proofs = [[p.decryptionShare, p.eqlogZKP.tup] for p in messagesWithZKP.proof]

            if verification_of_ballot_decrytion(pk, ciphertexts, message, proofs) is not True:
                if progressbar is not None:
                    progressbar.setValue(100)
                return False

            if progressbar is not None:
                progressbar.setValue(int((i * len(mixMixingPackets[i].ciphertexts) + (j + 1)) * 100 / (len(messages) * len(mixMixingPackets[i].ciphertexts))))

    if progressbar is not None:
        progressbar.setValue(100)
    return True


def load_registry(path):
    registryJSON = loadSecureJSON(path, "registry.json", sequence=False)
    registry = Registry(registryJSON)
    return registry


def printFailed():
    logger.info("                                                   [\033[1;31mFAILED\033[0;0m]")


def printOK():
    logger.info("                                                   [\033[1;32m  OK  \033[0;0m]")


def get_tallying_result_cmdline(tallying, registry, language=None):
    resulttxt = ""
    for struc in registry.ballotStructures:
        resulttxt += "\n\t[%s]: %s" % (struc.id, struc.title.value(language))
        for l in struc.lists:
            txt = l.columnHeaders[0].value(language) if len(l.columnHeaders) > 0 else "None"
            resulttxt += "\n\t\t[%s]: %s: %s  : %d" % (l.id, l.title.value(language), txt, tallying[struc.id][l.id + "forList"])
            for candidate in l.candidates:
                txt = candidate.columns[0].value.value(language) if len(candidate.columns) > 0 else "None"
                resulttxt += "\n\t\t\t[%s]: %s: %d" % (candidate.id, txt, tallying[struc.id][l.id][candidate.id])

    return resulttxt


def print_registry(path, language=None):
    registry = load_registry(path)
    s = registry.desc + (" " * 54)
    logger.info("----------------------------------------------------------")
    logger.info("+ \033[1;34m%s\033[0;0m +" % (s[:54]))
    logger.info("----------------------------------------------------------")
    for struc in registry.ballotStructures:
        logger.info("%s: %s" % (struc.id, struc.title.value(language)))
        logger.info("MaxVotes: %s" % (struc.maxVotes))
        logger.info("MinVotes: %s" % (struc.minVotes))
        logger.info("ShowInvalidOptions: %s" % (struc.showInvalidOption))
        if hasattr(struc, "contentAbove"):
            logger.info("%s" % struc.contentAbove.value.value(language))

        for l in struc.lists:
            logger.info("\tList: %s: %s" % (l.id, l.title.value(language)))
            logger.info("\tMaxVotesForList: %s" % (l.maxVotesForList))
            logger.info("\tMinVotesForList: %s" % (l.minVotesForList))
            logger.info("\tMaxVotesOnList: %s" % (l.maxVotesOnList))
            logger.info("\tMinVotesOnList: %s" % (l.minVotesOnList))
            for header in l.columnHeaders:
                logger.info("\t%s" % (header.value(language)))

            for candidate in l.candidates:
                logger.info("\t\tCandidate: %s" % candidate.id)
                for column in candidate.columns:
                    logger.info("\t\t + %s: %s" % (candidate.id, column.value.value(language)))


def do_tallying(path):
    """
    The function where the actual tallying is happening.
    :param path:
    :return:
    """

    tallying = {}
    rows = 0

    registry = load_registry(path)

    # Building up the structure of the tallying directory
    # The actual data is set in the next step
    for struc in registry.ballotStructures:
        tallying[struc.id] = {}
        rows += 1
        for l in struc.lists:
            rows += 1
            tallying[struc.id][l.id] = {}
            tallying[struc.id][l.id + "forList"] = 0
            for candidate in l.candidates:
                tallying[struc.id][l.id][candidate.id] = 0
                rows += 1

    logger.info("----------------------------------------------------------")
    logger.info("Tallying...")
    logger.info("----------------------------------------------------------")
    messagePackets = load_decryption_decrypt(path)

    # Filling in the data into the tallying structure
    for messagePacket in messagePackets:
        ballotSheets = messagePacket.publicLabel.split(":")
        for messageWithProof in messagePacket.messagesWithZKP:
            m = byte_reader(messageWithProof.message)
            for struc in registry.ballotStructures:
                # Information about number and spreading of votes on the entire ballot sheet
                votesForLists = 0
                listsWithVotes = 0
                votesOnCandidates = 0
                # Messages of packet do not contain votes for this ballot sheet
                if struc.id not in ballotSheets:
                    continue
                invalid = False
                # Ballot explicitly marked as invalid
                if next(m) == 1:
                    # NOW INVALID
                    logger.warning("Message marked as INVALID: %x" % int.from_bytes(messageWithProof.message, byteorder="big", signed=False))
                    invalid = True

                for l in struc.lists:
                    nex = next(m)
                    l.forListValue = nex
                    votesForLists += nex
                    # Check if number of votes given to a list is ok
                    if not invalid:
                        if nex < l.minVotesForList or nex > l.maxVotesForList:
                            logger.warning("%s - %s: ForList Votes: %d  (minForList: %d, maxForList: %d) INVALID" % (struc.id, l.id, nex, l.minVotesForList, l.maxVotesForList))
                            invalid = True

                    # Check if number of votes on candidates of a list is ok
                    votesOnList = 0
                    votes = []
                    writeInOnList = False
                    for i in range(len(l.candidates)):
                        if l.candidates[i].writeInSize > 0:
                            writeInBytes = bytearray()
                            for t in range(l.candidates[i]):
                                writeInBytes.append(next(m))
                            logger.info("%s - %s - %s: %s" % (struc.id, l.id, l.candidates[i].id, str(writeInBytes, "ASCII")))
                            writeInOnList = True
                        else:
                            nex = next(m)
                            # Check if number of votes for candidate is correct
                            if nex < l.candidates[i].minVotes or nex > l.candidates[i].maxVotes:
                                logger.warning("%s - %s - %s: Votes: %d  (min: %d, maxF: %d) INVALID" % (struc.id, l.id, l.candidates[i].id, nex, l.candidates[i].minVotes, l.candidates[i].maxVotes))
                                invalid = True
                            votesOnList += nex
                            votes.append(nex)

                    if not invalid and l.voteCandidateXorList and (l.forListValue > 0 or writeInOnList) and votesOnList > 0:
                        logger.info("%s - %s: Votes for both list and candidates not allowed INVALID" % (struc.id, l.id))
                        invalid = True
                    votesOnCandidates += votesOnList
                    if l.forListValue > 0 or votesOnList > 0:
                        listsWithVotes += 1
                    l.votes = votes

                    if not invalid:
                        if votesOnList < l.minVotesOnList or votesOnList > l.maxVotesOnList:
                            logger.warning("%s - %s: Votes on list: %d  (minVotesOnList: %d, maxVotesOnList: %d) INVALID" % (struc.id, l.id, votesOnList, l.minVotesOnList, l.maxVotesOnList))
                            invalid = True
                        elif votesOnList + l.forListValue < l.minVotesTotal or votesOnList + l.forListValue > l.maxVotesTotal:
                            logger.warning("%s - %s: Total votes: %d  (minVotesTotal: %d, maxVotesTotal: %d) INVALID" % (struc.id, l.id, votesOnList + l.forListValue, l.minVotesTotal, l.maxVotesTotal))
                            invalid = True

                if not invalid:
                    # Checking sum of votes for entire ballot sheet
                    if struc.maxListsWithChoices < listsWithVotes:
                        logger.warning("%s: ListsWithChoices: %d (maxListsWithChoices: %d) INVALID" % (struc.id, listsWithVotes, struc.maxListsWithChoices))
                        invalid = True

                    if votesOnCandidates + votesForLists > struc.maxVotes or votesOnCandidates + votesForLists < struc.minVotes:
                        logger.warning("%s: Total votes: %s (minVotes: %d, maxVotes: %d) INVALID" % (struc.id, listsWithVotes, struc.minVotes, struc.maxVotes))
                        invalid = True

                    if votesOnCandidates < struc.minVotesForCandidates or votesOnCandidates > struc.maxVotesForCandidates:
                        logger.warning("%s: Total votes for candidates: %d (minVotesForCandidates: %d, maxVotesForCandidates: %d) INVALID" % (struc.id, listsWithVotes, struc.minVotesForCandidates, struc.maxVotesForCandidates))
                        invalid = True

                    if votesForLists < struc.minVotesForLists or votesForLists > struc.maxVotesForLists:
                        logger.warning("%s: Total votes for lists: %d (minVotesForLists: %d, maxVotesForList: %d) INVALID" % (struc.id, listsWithVotes, struc.minVotesForLists, struc.maxVotesForLists))
                        invalid = True

                # Adding to final Tallying and logging decoded ballots
                if not invalid:
                    logger.info("Decoding ballot for ballot sheet %s" % struc.id)
                    for l in struc.lists:
                        tallying[struc.id][l.id + "forList"] += l.forListValue
                        if l.forListValue:
                            logger.info("Votes for list %s: %s" % (l.id, l.forListValue))
                        for i in range(len(l.candidates)):
                            tallying[struc.id][l.id][l.candidates[i].id] += l.votes[i]
                            if votes[i]:
                                logger.info("Votes for candidate %s: %s" % (l.candidates[i].id, votes[i]))

    return (tallying, rows)


def verify_second_device_public_parameters(path, phase1=None):
    accepted = True
    logger.info("----------------------------------------------------------")
    logger.info("VERIFYING")
    logger.info("----------------------------------------------------------")
    logger.info("Verifying the second device public parameters...")
    parametersJSON = {}
    fingerprint = ""
    try:
        parametersWithFingerprintJSON = loadSecureJSON(path, "secondDeviceParametersFingerprint.json", sequence=False, plain=True)
        parametersJSON = json.loads(parametersWithFingerprintJSON["publicParametersJson"])
        fingerprint = parametersWithFingerprintJSON["fingerprint"]
    except Exception:
        logger.info("No file with second device public parameters found: secondDeviceParametersFingerprint.json")
        if phase1:
            phase1.setValue(100)
            phase1.setStyleSheet(redStyle)
        logger.info("The second device public parameters are: [\033[1;31m NOT ACCEPTED \033[0;0m]")
        return False
    parameterBytes = build_bytearray_by_type(parametersWithFingerprintJSON["publicParametersJson"])
    fingerprintRecalc = hashlib.sha512(parameterBytes).hexdigest()
    registryJSON = loadSecureJSON(path, "registry.json", sequence=False)
    if fingerprint != fingerprintRecalc:
        logger.info("The fingerprint of the second device public parameters is invalid.")
        if phase1:
            phase1.setStyleSheet(redStyle)
        accepted = False
    if phase1:
        phase1.setValue(25)
    keygen = load_key_gen_election_key(path)
    verificationKey = ""
    try:
        verificationKey = loadSecureJSON(path, "bbox-ballotbox-key-cp.json", sequence=False)
    except Exception:
        logger.info("No file with verification key found: bbox-ballotbox-key-cp.json")
        if phase1:
            phase1.setValue(100)
            phase1.setStyleSheet(redStyle)
        logger.info("The second device public parameters are: [\033[1;31m NOT ACCEPTED \033[0;0m]")
        return False

    if parametersJSON["publicKey"] != keygen.publicKey.hex():
        logger.info("The public key of the second device public parameters is invalid.")
        if phase1:
            phase1.setStyleSheet(redStyle)
        accepted = False
    if phase1:
        phase1.setValue(50)

    if parametersJSON["verificationKey"] != verificationKey:
        logger.info("The verification key of the second device public parameters is invalid.")
        if phase1:
            phase1.setStyleSheet(redStyle)
        accepted = False
    if phase1:
        phase1.setValue(75)

    if parametersJSON["ballots"] != registryJSON["ballotStructures"]:
        logger.info("The ballots of the second device public parameters are invalid.")
        if phase1:
            phase1.setStyleSheet(redStyle)
        accepted = False
    if phase1:
        phase1.setValue(100)

    logger.info("----------------------------------------------------------")
    if accepted:
        logger.info("The second device public parameters are: [\033[1;32m   ACCEPTED   \033[0;0m]")
    else:
        logger.info("The second device public parameters are: [\033[1;31m NOT ACCEPTED \033[0;0m]")
    logger.info("")
    return accepted


def get_signature_if_valid(receiptPath: str, file: str, key: str, logTo=None):
    """

    Parameters
    ----------
    receiptPath : str
        path to the receipt files
    file : str
        current receipt file
    key : str
        Public key for signing receipts
    logto: storing logged ballots to a provided list

    Returns fingerprint if the file is valid, else None
    """
    f = open(os.path.join(receiptPath, file), 'rb')
    reader = PyPDF2.PdfReader(f)
    receipt = reader.pages[0].extract_text().replace("\n", "")
    f.close()
    fingerprintList = re.findall(r".*BEGIN FINGERPRINT----- ?([0-9|a-f]*) ?-----END FINGERPRINT.*", receipt)

    signList = re.findall(r".*BEGIN SIGNATURE----- ?(.*) ?-----END SIGNATURE.*", receipt)
    if len(fingerprintList) != 1 or len(signList) != 1:
        logger.info("The ballot cast confirmation file %s does not have the correct format." % file)
        if logTo:
            logTo.append({"status": ReceiptStatus.MALFORMED, "file": file})
        return None
    if not verify_signature_rsa(fingerprintList[0], signList[0], key):
        logger.info("The ballot cast confirmation file %s does not contain a valid signature." % file)
        if logTo:
            logTo.append({"status": ReceiptStatus.INVALID, "file": file})
        return None
    return fingerprintList[0]


def verify_receipts(path, phase1=None, log=False, logTo=None):
    valid = True
    verificationKey = None
    receiptPath = os.path.join(path, "receipts")
    try:
        verificationKey = loadSecureJSON(path, "bbox-ballotbox-key-cp.json", sequence=False)
        if phase1:
            phase1.setValue(25)
    except Exception:
        logger.info("No file with verification key found: bbox-ballotbox-key-cp.json")
        if phase1:
            phase1.setValue(100)
            phase1.setStyleSheet(redStyle)
        logger.info("The ballot cast confirmations are: [\033[1;31m NOT ACCEPTED \033[0;0m]")
        return False

    if not os.path.exists(receiptPath):
        logger.info("No folder with ballot cast confirmations found.")
        if phase1:
            phase1.setValue(100)
            phase1.setStyleSheet(redStyle)
        logger.info("The ballot cast confirmations are: [\033[1;31m NOT ACCEPTED \033[0;0m]")
        return False

    if phase1:
        phase1.setValue(50)

    ballots = load_ballot_box_flagged(path)
    # Stores the index of each ballot by its fingerprint
    ballotsByFingerprint = {}
    for t in range(len(ballots)):
        ballotsByFingerprint[ballots[t].ballot.fingerprint()] = t
    files = os.listdir(receiptPath)
    totalConfirmationsFound = 0
    for t in range(len(files)):
        fingerprint = get_signature_if_valid(receiptPath, files[t], verificationKey, logTo)
        if fingerprint and fingerprint not in ballotsByFingerprint:
            logger.info("The ballot %s is not included in the ballot box." % fingerprint)
            if logTo is not None:
                logTo.append({"status": ReceiptStatus.MISSING, "fingerprint": fingerprint})
            valid = False
            if phase1:
                phase1.setStyleSheet(redStyle)
        elif fingerprint and ballotsByFingerprint[fingerprint] is None:
            logger.info("Multiple receipts for ballot %s found." % fingerprint)
            if logTo is not None:
                logTo.append({"status": ReceiptStatus.CLASH, "fingerprint": fingerprint})
            valid = False
            if phase1:
                phase1.setStyleSheet(redStyle)
        elif fingerprint:
            status = ballots[ballotsByFingerprint[fingerprint]].status
            logger.info("The ballot %s is included in the ballot box with status %s." % (fingerprint, status))
            if logTo is not None:
                logTo.append({"status": ReceiptStatus.PRESENT, "fingerprint": fingerprint, "ballotStatus": status})
            totalConfirmationsFound += 1
            ballotsByFingerprint[fingerprint] = None

        if phase1:
            phase1.setValue(50 + math.ceil(50 / len(files) * (t + 1)))
    close_gpg()

    logger.info("Total number of ballots checked: %s" % totalConfirmationsFound)

    logger.info("----------------------------------------------------------")
    if valid:
        logger.info("The ballot cast confirmations are: [\033[1;32m   ACCEPTED   \033[0;0m]")
    else:
        logger.info("The ballot cast confirmations are: [\033[1;31m NOT ACCEPTED \033[0;0m]")
        if phase1:
            phase1.setStyleSheet(redStyle)
    logger.info("")
    return valid


def checking_files(path):
    logger.info("----------------------------------------------------------")
    logger.info("Testing path: %s" % path)
    load_registry(path)
    load_ballot_box(path)
    load_ballot_box_flagged(path)
    load_revocation_authorisation(path)
    load_revocation_tokens(path)
    load_ballot_box_filtered_out(path)
    load_decryption_decrypt(path)
    load_mixing_input_packets(path)
    load_mixing_mix(path)
    logger.info("----------------------------------------------------------")


def verification(path, accepted, phase1=None, phase2=None, phase3=None, phase4=None, phase5=None):
    logger.info("----------------------------------------------------------")
    logger.info("VERIFYING")
    logger.info("----------------------------------------------------------")
    logger.info("Verifying the public election key with zero-knowledge proof...")
    if verify_public_election_key(path, phase1) is not True:
        printFailed()
        accepted = False
        if phase1:
            phase1.setStyleSheet(redStyle)
    else:
        printOK()
        if phase1:
            phase1.setStyleSheet(greenStyle)

    logger.info("Verifying ballot box...")
    if verify_ballot_box(path, phase2) is not True:
        printFailed()
        accepted = False
        if phase2:
            phase2.setStyleSheet(redStyle)
    else:
        printOK()
        if phase2:
            phase2.setStyleSheet(greenStyle)

    logger.info("Verifying ballot decryption...")
    if verify_ballot_decryption(path, phase3) is not True:
        printFailed()
        accepted = False
        if phase3:
            phase3.setStyleSheet(redStyle)
    else:
        printOK()
        if phase3:
            phase3.setStyleSheet(greenStyle)

    logger.info("Verifying mixing packets...")
    if verify_mixing_input(path, phase4) is not True:
        printFailed()
        accepted = False
        if phase4:
            phase4.setStyleSheet(redStyle)
    else:
        printOK()
        if phase4:
            phase4.setStyleSheet(greenStyle)

    logger.info("Verifying shuffle...")
    if verify_shuffle(path, phase5) is not True:
        printFailed()
        accepted = False
        if phase5:
            phase5.setStyleSheet(redStyle)
    else:
        printOK()
        if phase5:
            phase5.setStyleSheet(greenStyle)

    logger.info("----------------------------------------------------------")
    if accepted:
        logger.info("Election files are:      [\033[1;32m   ACCEPTED   \033[0;0m]")
    else:
        logger.info("Election files are:      [\033[1;31m NOT ACCEPTED \033[0;0m]")
    logger.info("")

    return accepted


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog='polyas_checker.py',
        description='Program to check the election results (universal verification) of a polyas election',
        epilog='')

    parser.add_argument('path', type=str, help='The absolute path to the polyas verification files.')
    parser.add_argument('-s', '--second-device', action='store_true', dest='sdpp', help='Polyas-Checker will verify second device public parameters.')
    parser.add_argument('-r', '--receipts', action='store_true', dest='rec', help='Polyas-Checker will check ballot cast confirmations in folder \receipts\'.')
    parser.add_argument('--log', action='store_true', dest='list', help='Polyas-Checker will log additional information for ballot cast confirmations.')
    parser.add_argument('-l', '--language', type=str, help="Set preferred language")
    args = parser.parse_args()

    logger.info("\033[0;0m")
    logger.info("Polyas-Checker")
    logger.info("Running version " + VERSION)

    accepted = True
    path = str(args.path)
    try:
        checking_files(path)
    except FileNotFoundError as error:
        logger.info("File missing: " + str(error))
        exit(0)

    print_registry(path, args.language)
    (tallying, rows) = do_tallying(path)

    logger.info(get_tallying_result_cmdline(tallying, load_registry(path), args.language))

    verification(path, accepted)

    if args.sdpp:
        verify_second_device_public_parameters(path)

    if args.rec:
        verify_receipts(path, None, log=args.list)
