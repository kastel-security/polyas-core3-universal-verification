#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Christoph Niederbudde
import unittest
import sys
import logging
import json
from parameterized import parameterized
from app.helper.classes import BallotBoxEntry
from app.polyas_checker import verify_ballot_box, verify_mixing_input, get_signature_if_valid, initialize_gpg
from app.helper.secureJSON import loadSecureJSON

logger = logging.getLogger()
logger.level = logging.DEBUG
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)


class BallotBoxFlaggedTestClass(unittest.TestCase):
    @parameterized.expand([["different_ballots",
                            "Ballot of voter voter4 incorrectly transferred from ballot-box to ballot-box-flagged"],
                           ["invalid_ok",
                            "Ballot of voter voter0 incorrectly flagged: Expected INCORRECT but was OK"],
                           ["invalid_revoked",
                            "Ballot of voter voter2 incorrectly flagged: Expected INCORRECT but was REVOKED"],
                           ["ok_invalid",
                            "Ballot of voter voter0 incorrectly flagged: Expected OK but was INCORRECT"],
                           ["ok_revoked",
                            "Ballot of voter voter0 incorrectly flagged: Expected OK but was REVOKED"],
                           ["revoked_ok",
                            "Ballot of voter voter2 incorrectly flagged: Expected REVOKED but was OK"],
                           ["revoked_invalid",
                            "Ballot of voter voter2 incorrectly flagged: Expected REVOKED but was INCORRECT"]])
    def test_invalid(self, dataset, result):
        path = "../data/ballot_board_flagged/invalid/"
        with self.assertLogs() as captured:
            valid = verify_ballot_box(path + dataset)
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(captured.records[0].getMessage(), result)
        self.assertFalse(valid)

    @parameterized.expand([["ballot_duplication"], ["ballot_not_well_formed"], ["invalid_ciphertext_length"],
                           ["invalid_public_credential"], ["voter_not_registered"]])
    def test_valid(self, dataset):
        path = "../data/ballot_board_flagged/valid_with_invalid_ballots/"
        valid = verify_ballot_box(path + dataset)
        self.assertTrue(valid)


class InputMixPacketsTestClass(unittest.TestCase):
    @parameterized.expand([["packet_to_small", "A packet on board mixing-input-packets for public label 0 has an invalid size"],
                          ["packet_to_large", "A packet on board mixing-input-packets for public label 0 has an invalid size"],
                          ["ballot_stuffing", "Board mixing-input-packets contains additional ballots"],
                          ["ballot_removed", "Board mixing-input-packets misses ballot of voter voter2"],
                          ["ballot_replaced", "Board mixing-input-packets misses ballot of voter voter2"]])
    def text_invalid(self, folder, result):
        path = "../data/ballot_mixing_packets/invalid/"
        with self.assertLogs() as captured:
            valid = verify_mixing_input(path + folder)
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(captured.records[0].getMessage(), result)
        self.assertFalse(valid)

    @parameterized.expand([["empty_packet", "valid_mixing_packets"]])
    def text_valid(self, folder):
        path = "../data/ballot_mixing_packets/valid/"
        valid = verify_mixing_input(path + folder)
        self.assertTrue(valid)


class ReceiptTestClass(unittest.TestCase):
    def testValidFingerprint(self):
        content = """
        {
            "publicLabel" : "A",
            "voterID" : "03b36cfc60f1fa86a5826bb5377fe6ec123045df33652516101ae803cca57b4276",
            "ballot" : {
                "encryptedChoice" : {
                    "ciphertexts" : [ {
                        "x" : "0201df95626718539000d65a8049f2418328df95a61107357b96db2f5dc304b38b",
                        "y" : "03692902cdfc6febebcd1d175859a6ea84018fe47c345f5e44fffddf97a492112f"
                        } ]
                    },
                "proofOfKnowledgeOfEncryptionCoins" : [ {
                    "c" : "101884463475449792123435889591575651216237787976278053756254664400615609849402",
                    "f" : "81174399198084050819276673106811016645306940417447240994496938329622216775741"
                    } ],
                "proofOfKnowledgeOfPrivateCredential" : {
                    "c" : "74448678640965672610706594238871799913455885364649021819048000651594839644426",
                    "f" : "33276182696803028530168279419966710636866170477238993593368673329284148491287"
                    }
                },
            "publicCredential" : "03b36cfc60f1fa86a5826bb5377fe6ec123045df33652516101ae803cca57b4276"
        }
        """
        expected = "534a6f16ae3f3e77e971d16bc4893c680824b5f16a882dfe299c629e33870dc3"

        ballot = BallotBoxEntry(json.loads(content))
        val = ballot.fingerprint()
        self.assertEquals(val, expected)

    def testValidReceipt(self):
        path = "../data/full_doc_ext"
        key = loadSecureJSON(path, "BBox-ballotbox-key-CP.json")
        gpg = initialize_gpg([key])
        self.assertNotEqual(get_signature_if_valid(path + "/receipts", "b1.pdf", gpg, key), None)

    def testInvalidReceipt(self):
        path = "../data/full_doc_ext"
        key = loadSecureJSON(path, "BBox-ballotbox-key-CP.json")
        gpg = initialize_gpg([key])
        self.assertEqual(get_signature_if_valid(path + "/receipts", "b2.pdf", gpg, key), None)


class SeconDevicePublicParametersTestClass(unittest.testCase):
    @parameterized.expand([])
    def test_invalid(self, dataset, log, index):
        path = "../data/ballot_board_flagged/invalid/"
        with self.assertLogs() as captured:
            valid = verify_ballot_box(path + dataset)
        self.assertTrue(len(captured.records) > index)
        self.assertEqual(captured.records[index].getMessage(), log)
        self.assertFalse(valid)

    @parameterized.expand([])
    def test_valid(self, dataset):
        path = "../data/ballot_board_flagged/valid_with_invalid_ballots/"
        valid = verify_ballot_box(path + dataset)
        self.assertTrue(valid)


if __name__ == "__main__":
    unittest.main()
