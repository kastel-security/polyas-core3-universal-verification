#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde

from algos.algorithms import build_bytearray_by_type
from algos.secp256k1 import secp256k1_p as p
import hashlib
import math
from enum import Enum

ReceiptStatus = Enum('ReceiptStatus', ['MALFORMED', 'INVALID', 'MISSING', 'PRESENT'])
BallotStatus = Enum('BallotStatus', ['OK', 'INCORRECT', 'REVOKED'])

class AnnotatedBallot():
    def __init__(self, annotatedJSON):
        if type(annotatedJSON) == str:
            self.status = "REVOKED"
        else:
            self.ballot = BallotBoxEntry(annotatedJSON["ballot"])
            self.annotation = annotatedJSON["annotation"] # String
            try:
                self.status = BallotStatus[annotatedJSON["status"]]
            except:
                print(annotatedJSON["status"])
                raise Exception("AnnontatedBallot status is neither OK, INCORRECT nor REVOKED! Status is %s" % self.status)

class Ciphertext():
    def __init__(self,ciphertextJSON):
        self.x = bytearray.fromhex(ciphertextJSON["x"]) # GroupElement
        self.y = bytearray.fromhex(ciphertextJSON["y"]) # GroupElement
        self.tup = (self.x,self.y)
        #TODO check both for group element
    def __eq__(self, other):
        assert isinstance(other, Ciphertext)
        return self.x == other.x and self.y == other.y


class DlogNIZKP():
	def __init__(self,nizkpJSON):
		self.c = int(nizkpJSON["c"])  # BigInt
		self.f = int(nizkpJSON["f"])  # BigInt
		self.tup = (self.c,self.f)

class EqlogNIZKP():
	def __init__(self,nizkpJSON):
		self.c = int(nizkpJSON["c"])  # BigInt
		self.f = int(nizkpJSON["f"])  # BigInt
		self.tup = (self.c, self.f)

class MultiCiphertext():
    def __init__(self,encryptedChoiceJSON):
        self.ciphertexts = [Ciphertext(i) for i in encryptedChoiceJSON["ciphertexts"]]
    def __eq__(self, other):
        assert isinstance(other, MultiCiphertext)
        equal = True
        for i in range(len(self.ciphertexts)):
            equal = False if not self.ciphertexts[i].__eq__(other.ciphertexts[i]) else True
        return equal


class Ballot():
    def __init__(self,ballotJSON):
        self.encryptedChoice = MultiCiphertext(ballotJSON["encryptedChoice"])
        self.proofOfKnowledgeOfEncryptionCoins = [DlogNIZKP(i) for i in ballotJSON["proofOfKnowledgeOfEncryptionCoins"]]
        self.proofOfKnowledgeOfPrivateCredential = DlogNIZKP(ballotJSON["proofOfKnowledgeOfPrivateCredential"])
    def __eq__(self, other):
        # Ballots are counted as equal if they have the same encrypted choice, even if the proofs are different
        assert isinstance(other, Ballot)
        return self.encryptedChoice.__eq__(other.encryptedChoice)

class BallotBoxEntry():
    def __init__(self,ballotBoxEntryJSON):
        self.publicLabel = ballotBoxEntryJSON["publicLabel"] # String
        self.voterID = ballotBoxEntryJSON["voterID"] # String
        self.publicCredential = bytearray.fromhex(ballotBoxEntryJSON["publicCredential"]) # GroupElement
        self.ballot = Ballot(ballotBoxEntryJSON["ballot"])
    def __eq__(self, other):
        assert isinstance(other, BallotBoxEntry)
        return self.publicLabel == other.publicLabel and self.voterID == other.voterID and self.publicCredential == other.publicCredential and self.ballot.__eq__(other.ballot)
    def fingerprint(self):
        digestion = bytearray()
        digestion.extend(build_bytearray_by_type([len(self.publicLabel), self.publicLabel]))
        digestion.extend(build_bytearray_by_type([len(self.publicCredential), self.publicCredential]))
        digestion.extend(build_bytearray_by_type([len(self.voterID), self.voterID]))
        digestion.extend(build_bytearray_by_type(len(self.ballot.encryptedChoice.ciphertexts)))
        for text in self.ballot.encryptedChoice.ciphertexts:
            digestion.extend(build_bytearray_by_type([len(text.x), text.x, len(text.y), text.y]))
        digestion.extend(build_bytearray_by_type(len(self.ballot.proofOfKnowledgeOfEncryptionCoins)))

        for proof in self.ballot.proofOfKnowledgeOfEncryptionCoins:
            lc = math.ceil((math.log(proof.c, 2) + 1) / 8)
            lf = math.ceil((math.log(proof.f, 2) + 1) / 8)
            digestion.extend(build_bytearray_by_type([lc, bytearray(proof.c.to_bytes(lc, "big"))]))
            digestion.extend(build_bytearray_by_type([lf, bytearray(proof.f.to_bytes(lf, "big"))]))

        proof = self.ballot.proofOfKnowledgeOfPrivateCredential
        lc = math.ceil((math.log(proof.c, 2) + 1) / 8)
        lf = math.ceil((math.log(proof.f, 2) + 1) / 8)
        digestion.extend(build_bytearray_by_type([lc, bytearray(proof.c.to_bytes(lc, "big"))]))
        digestion.extend(build_bytearray_by_type([lf, bytearray(proof.f.to_bytes(lf, "big"))]))

        return hashlib.sha256(digestion).hexdigest()

class ZKPt():
	def __init__(self, zkptJSON):
		self.t1 = bytearray.fromhex(zkptJSON["t1"])
		self.t2 = bytearray.fromhex(zkptJSON["t2"])
		self.t3 = bytearray.fromhex(zkptJSON["t3"])

		assert len(zkptJSON["t4x"]) == len(zkptJSON["t4y"])
		self.t4 = [( bytearray.fromhex(zkptJSON["t4x"][i]), bytearray.fromhex(zkptJSON["t4y"][i]) ) for i in range(len(zkptJSON["t4x"]))]

		self.tHat = [bytearray.fromhex(x) for x in zkptJSON["tHat"]]

class ZKPs():
	def __init__(self, zkpsJSON):
		self.s1 = int(zkpsJSON["s1"]) # BigInt
		self.s2 = int(zkpsJSON["s2"]) # BigInt
		self.s3 = int(zkpsJSON["s3"]) # BigInt
		self.s4 = [ int(x) for x in zkpsJSON["s4"]] # List of BigInt
		self.sHat = [ int(x) for x in zkpsJSON["sHat"]]  # List of BigInt
		self.sPrime = [ int(x) for x in zkpsJSON["sPrime"]]  # List of BigInt

class ShuffleZKP():
	def __init__(self,shuffleZKProofJSON):
		self.t = ZKPt(shuffleZKProofJSON["t"])
		self.s = ZKPs(shuffleZKProofJSON["s"])
		self.c = [bytearray.fromhex(x) for x in shuffleZKProofJSON["c"]] # List of GroupElements
		self.cHat = [bytearray.fromhex(x) for x in shuffleZKProofJSON["cHat"]] # List of GroupElements

class MixPacket():
	def __init__(self, mixPacketJSON):
		if "proof" in mixPacketJSON:
			self.proof = ShuffleZKP(mixPacketJSON["proof"]) # c, cHat, t1, t2, t3 ... / NULL

		self.ciphertexts = [MultiCiphertext(i) for i in mixPacketJSON["ciphertexts"]] # List of Multiciphertexts
		self.publicLabel = mixPacketJSON["publicLabel"] # String

class PublicKeyWithZKP():
	def __init__(self,keyGenElectionKeyJSON):
		self.publicKey = bytearray.fromhex(keyGenElectionKeyJSON["publicKey"])
		self.zkp = DlogNIZKP(keyGenElectionKeyJSON["zkp"])

class DecryptionZKP():
	def __init__(self, decryptionZKPJSON):
		self.decryptionShare = bytearray.fromhex(decryptionZKPJSON["decryptionShare"]) # GroupElement
		self.eqlogZKP = EqlogNIZKP(decryptionZKPJSON["eqlogZKP"])

class MessageWithProof():
	def __init__(self, messageJSON):
		self.message = bytearray.fromhex(messageJSON["message"]) # Bytearray
		self.proof = [ DecryptionZKP(x) for x in messageJSON["proof"]] # List of DecryptionZKP Proof

class MessageWithProofPacket():
	def __init__(self, messagesJSON):
		self.publicLabel = messagesJSON["publicLabel"] # String
		self.messagesWithZKP = [MessageWithProof(x) for x in messagesJSON["messagesWithZKP"]] # List of MessageWithProof

class I18n():
    def __init__(self, I18nJSON):
        self.default = I18nJSON["default"]
        self.values = I18nJSON["value"]
    def value(self, language = None):
        if language and language in self.values:
            return self.values[language]
        else:
            return self.default

class Content():
	def __init__(self, contentJSON):
		self.contentType = contentJSON["contentType"]
		self.value = I18n(contentJSON["value"])

class CandidateSpec():
    def __init__(self, candidateSpecJSON):
        self.id = candidateSpecJSON["id"] # String
        self.maxVotes = int(candidateSpecJSON["maxVotes"]) # Int
        self.minVotes = int(candidateSpecJSON["minVotes"])  # Int
        self.columns = [ Content(x) for x in candidateSpecJSON["columns"]]
        self.writeInSize = int(candidateSpecJSON["writeInSize"]) if "writeInSize" in candidateSpecJSON else 0 # Int

class CandidateList():
    def __init__(self, candidateListJSON):
        self.candidates = [ CandidateSpec(x) for x in candidateListJSON["candidates"]] # List of CandidateSpec
        self.id = candidateListJSON["id"] # String
        self.maxVotesForList = int(candidateListJSON["maxVotesForList"]) # Int
        self.maxVotesOnList = int(candidateListJSON["maxVotesOnList"])  # Int
        self.minVotesForList = int(candidateListJSON["minVotesForList"])  # Int
        self.minVotesOnList = int(candidateListJSON["minVotesOnList"])  # Int
        self.maxVotesTotal = int(candidateListJSON["maxVotesTotal"]) if "maxVotesTotal" in candidateListJSON else float("inf") # Int or ininity
        self.minVotesTotal = int(candidateListJSON["minVotesTotal"]) if "minVotesTotal" in candidateListJSON else 0 # Int
        self.voteCandidateXorList = bool(candidateListJSON["voteCandidateXorList"]) if "voteCandidateXorList" in candidateListJSON else False # Int
        try:
            self.title = I18n(candidateListJSON["title"]) # I18n
        except KeyError:
            self.title = I18n({"default":"No title","value":{}}) # I18n

        if len(candidateListJSON["columnHeaders"]) == 0:
            self.columnHeaders = [I18n({"default":"","value":{}})]
        else:
            try:
                self.columnHeaders = [ I18n(x) for x in candidateListJSON["columnHeaders"]]
            except KeyError:
                self.columnHeaders = [ I18n({"default":"No name","value":{}}) for x in candidateListJSON["columnHeaders"]]

class Core3Ballot():
    def __init__(self, core3BallotJSON):
        self.id = core3BallotJSON["id"] # String
        self.lists = [ CandidateList(x) for x in core3BallotJSON["lists"]] # List of CandidateLists
        self.maxVotes = int(core3BallotJSON["maxVotes"]) # Int
        self.minVotes = int(core3BallotJSON["minVotes"]) # Int
        self.showInvalidOption = bool(core3BallotJSON["showInvalidOption"]) # Boolean
        self.title = I18n(core3BallotJSON["title"]) # I18n
        self.maxListsWithChoices = int(core3BallotJSON["maxListsWithChoices"]) if "maxListsWithChoices" in core3BallotJSON else float("inf") # Int or infinity
        self.maxVotesForCandidates = int(core3BallotJSON["maxVotesForCandidates"]) if "maxVotesForCandidates" in core3BallotJSON else float("inf") # Int or infinity
        self.maxVotesForLists = int(core3BallotJSON["maxVotesForLists"]) if "maxVotesForLists" in core3BallotJSON else float("inf") # Int or infinity
        self.minVotesForCandidates = int(core3BallotJSON["minVotesForCandidates"]) if "minVotesForCandidates" in core3BallotJSON else 0 # Int
        self.minVotesForLists = int(core3BallotJSON["minVotesForLists"]) if "minVotesForLists" in core3BallotJSON else 0 # Int
        if "contentAbove" in core3BallotJSON:
            self.contentAbove = Content(core3BallotJSON["contentAbove"])
        if "contentBelow" in core3BallotJSON:
            self.contentBelow = Content(core3BallotJSON["contentBelow"])


class Voter():
	def __init__(self, voterJSON):
		self.publicLabel = voterJSON["publicLabel"] # String
		self.voterId = voterJSON["id"] # String
		self.cred = bytearray.fromhex(voterJSON["cred"]) # GroupElement)

class Registry():
    def __init__(self, registryJSON):
        self.ballotStructures = [ Core3Ballot(x) for x in registryJSON["ballotStructures"]] # List of Core3Ballot
        self.packetSize = registryJSON["packetSize"] # Int
        self.voters = [ Voter(x) for x in registryJSON["voters"]] # List of Voters
        self.desc = registryJSON["desc"] # String
        self.electionId = registryJSON["electionId"] # Unknown
        self.ballotSigningKey = registryJSON["ballotSigningKey"] # Unknown
        self.revocationPolicy = RevocationPolicy(registryJSON["revocationPolicy"]) if "revocationPolicy" in registryJSON else None

class RevocationPolicy():
    def __init__(self, policyJSON):
        self.threshold = policyJSON["threshold"] # Int
        self.verificationKeys = policyJSON["verificationKeys"] # List of String

class RevocationToken():
    def __init__(self, tokenJSON):
        self.electionId = tokenJSON["electionId"] # String
        self.voterIds = tokenJSON["voterIds"] # List of String
    def normalized(self):
        fingerprintTemplate  = "REVOCATION_TOKEN{ELECTION=%s,VOTERS=[%s]}"
        return fingerprintTemplate % (str(self.electionId), ",".join(self.voterIds))

class RevocationTokenAuthorisation():
    def __init__(self, authorisationJSON):
        self.publicKey = authorisationJSON["publicKey"] # String
        self.signature = authorisationJSON["signature"] # String
        self.tokenFingerprint = authorisationJSON["tokenFingerprint"] # String

class SecondDevicePublicParameters():
    def __init__(self, parametersJSON, fingerprint):
        self.publicKey = parametersJSON["publicKey"] # String
        self.verificationKey = parametersJSON["verificationKey"] # String
        self.ballots = parametersJSON["ballots"] # String
        self.fingerprint = fingerprint # String
        self.rawJSON = parametersJSON
