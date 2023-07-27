#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde
import unittest
from algos.algorithms import numbers_from_seed, kdf, numbers_from_seed_range, build_bytearray_by_type, uniform_hash, revocation_token_fingerprint, independent_generators_for_ec_groups_of_prime_order
from algos.secp256k1 import Point, Curve, secp256k1_q

class NumbersFromSeedTestClass(unittest.TestCase):
    """
    unittest.TestCase for algorithm 2
    """
    def test_from_doc(self):
        """

        :return:
        """
        gen = numbers_from_seed(520, bytearray("xyz".encode("utf-8")))
        i = 0
        for r in gen:
            if i == 0:
                self.assertEqual(r,1732501504205220402900929820446308723705652945081825598593993913145942097001127020633138020218038968109094917857329663184563374015879596834703721749398989648)
            elif i == 1:
                self.assertEqual(r, 2207401303665503434031531355511922974889692817601183500259263742625914061046146142929376778072827450461936300533206904979740474482058840003720379960491023511)
            elif i == 2:
                self.assertEqual(r,1883889587903519477357838514223953979954201344665681798367023196328721975720052153913582122151913785273222921786889836987731296728825119604809609410157987402)
            elif i == 3:
                self.assertEqual(r,1423259849467217711185874799515607842842602785767879766623736284680209832704638390900412597196948750015976271793930713744890547611655064835165883323889981463)
            else:
                break
            i = i + 1

    def test_from_alg_4_testcase_2(self):
        """

        :return:
        """
        b = bytearray.fromhex("4e9bc4d8957bf9b0823847c42fb170c958dda6b36d671acc4c5ea02e165586cc91d444e68c3a817c28631aa09695b6db2085f8282f1edd6c36e9184eacd91ecb")
        gen = numbers_from_seed(31, b)
        for r in gen:
            self.assertEqual(r,1444258901)
            break

class KeyDerivationFunctionTestClass(unittest.TestCase):
    """
    unittest.TestCase for algorithm 1
    """
    def test_from_doc(self):
        """

        :return:
        """
        r = kdf(65, bytearray("kdk".encode("utf-8")), bytearray("label".encode("utf-8")), bytearray("context".encode("utf-8")))
        self.assertTrue(r[0] == 0x32)
        self.assertTrue(r[1] == 0x88)
        self.assertTrue(r[64] == 0x75)
        self.assertTrue(len(r) == 65)

class NumbersFromSeedRangeTestClass(unittest.TestCase):
    """
    unittest.TestCase for algorithm 3
    """
    def test_from_doc(self):
        """

        :return:
        """
        gen = numbers_from_seed_range(
            1732501504205220402900929820446308723705652945081825598593993913145942097001127020633138020218038968109094917857329663184563374015879596834703721749398989648 + 1,
            bytearray("xyz".encode("utf-8")))
        i = 0
        for n in gen:
            if i == 0:
                self.assertEqual(n,1732501504205220402900929820446308723705652945081825598593993913145942097001127020633138020218038968109094917857329663184563374015879596834703721749398989648)
            elif i == 1:
                self.assertEqual(n,1423259849467217711185874799515607842842602785767879766623736284680209832704638390900412597196948750015976271793930713744890547611655064835165883323889981463)
            else:
                break
            i = i+1

class BuildByteArrayByTypeTestClass(unittest.TestCase):
    """
    unittest.TestCase for BuildByteArrayByType(...) function. This function is just a helperfunction.
    """
    def test_good_cases(self):
        """

        :return:
        """
        self.assertEqual(build_bytearray_by_type("test"), bytearray([0x74, 0x65, 0x73, 0x74]))
        self.assertEqual(build_bytearray_by_type(4), bytearray([0x00, 0x00, 0x00, 0x04]))
        self.assertEqual(build_bytearray_by_type(98162874527223464716009286152), bytearray(
            [0x00, 0x00, 0x00, 0x0d, 0x01, 0x3D, 0x2E, 0x6D, 0x3A, 0xFD, 0xEC, 0x0F, 0x0A, 0x00, 0xAD, 0x2A, 0x08]))
        self.assertEqual(build_bytearray_by_type((1, 2)), bytearray([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02]))
        self.assertNotEqual(build_bytearray_by_type((bytearray([0x00, 0x11]), bytearray([0x11, 0x12]))), bytearray())

    def test_ecc_cases_bytearray(self):
        """

        :return:
        """
        compressed_key = bytearray.fromhex("0275788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b")
        x = bytearray.fromhex("75788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b")
        y = bytearray.fromhex("664663757d16eff0b993ac12a1ba16ee4784ac08206b12be50f4d954d9d74c88")
        self.assertEqual(build_bytearray_by_type(Point(x, y)), compressed_key)

    def test_ecc_cases_int(self):
        """

        :return:
        """
        compressed_key = bytearray.fromhex("0275788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b")
        x = int.from_bytes(bytearray.fromhex("75788b8a22a04baad44c66ec80e86928597979bf1b287760ad4e3153293d613b"),byteorder="big",signed=False)
        y = int.from_bytes(bytearray.fromhex("664663757d16eff0b993ac12a1ba16ee4784ac08206b12be50f4d954d9d74c88"),byteorder="big",signed=False)
        self.assertEqual(build_bytearray_by_type(Point(x, y)), compressed_key)

    def test_exception_cases(self):
        """

        :return:
        """
        self.assertRaises(Exception, build_bytearray_by_type, ("test", 2))

    def test_points_compressed_and_uncompressed(self):
        """

        :return:
        """
        curve = Curve()

        e = [
            bytearray.fromhex("0296EA334615B205F2B75AED751586FBFBFF794B4F96780146E55A11D3ED5447BF"),
            bytearray.fromhex("0237A9A3B7738311C6F36D954A8CAB89A697FD8AEF38676D732EC44FB978269F26"),
            bytearray.fromhex("029701753C446CCAF47A37D6AC28107AB026DD914D77989D36CF0F9319D161297F"),
            bytearray.fromhex("03793ED5EE4A3CD89BD74C4AE44E88614845B72702FCA623F54EEDE5821F7F453C")
        ]

        points = []
        for p in e:
            pt = curve.decompress(p)
            assert pt.valid()
            points.append(pt)
            self.assertEqual(uniform_hash(curve.q, p), uniform_hash(curve.q, pt))

        self.assertEqual(uniform_hash(curve.q, *e), uniform_hash(curve.q, *points))

class BasicHashTestClass(unittest.TestCase):
    @unittest.skip("Inconsistency in polyas specification document")
    def test_revocation_token(self):
        token = "REVOCATION_TOKEN{ELECTION=XA78,VOTERS=[voter501,voter809]}"
        self.assertEqual(revocation_token_fingerprint(secp256k1_q, token), "1f515cc47433d46a89be")

class UniformHashTestClass(unittest.TestCase):
    """
    unittest.TestCase for the uniformHash(..) function. (Algorithm 4)
    """
    def test_from_doc(self):
        """

        :return:
        """
        self.assertEqual(uniform_hash(2126991829, "some data"), 414907466)
        self.assertEqual(uniform_hash(2126991829, "some data", 98162874527223464716009286152), 1444258901)

class IndependentGeneratorsForECGroupsOfPrimeOrderTestClass(unittest.TestCase):
    """
    unittest.TestCase for algorithm 7
    """
    def test_from_doc(self):
        """

        :return:
        """
        curve = Curve()

        for i in range(1,4):
            p = independent_generators_for_ec_groups_of_prime_order(curve.p, curve.a, curve.b, bytearray("seed".encode("utf-8")), i)
            if i == 1:
                self.assertEqual(p.x,int.from_bytes(bytearray.fromhex("879f580dfe31c74dc2b4289f1988e581c76e625761a863971c808e90ab6fd3c7"), byteorder="big", signed=False))
                self.assertEqual(p.y, int.from_bytes(
                    bytearray.fromhex("4c59d9061d35678d06c04fe9f61dd47d7ee9e35b9847e5f3f9ed532c509afc0f"), byteorder="big", signed=False))
            if i == 2:
                self.assertEqual(p.x,int.from_bytes(bytearray.fromhex("b6413eb866319a631509ad0e637ec260507383d7495ef66858f9a6a4bb8efac7"), byteorder="big", signed=False))
                self.assertEqual(p.y, int.from_bytes(
                    bytearray.fromhex("adb88f8cdd62aad64e2518d383b4e6aa2013910964b6423c17c0100f96118ae1"), byteorder="big", signed=False))
            if i == 3:
                self.assertEqual(p.x,int.from_bytes(bytearray.fromhex("1845cc619ec1a70c743e6559938290b7dac3d63b3fd2cf8d6e0646d292a576e8"), byteorder="big", signed=False))
                self.assertEqual(p.y, int.from_bytes(
                    bytearray.fromhex("439f7d97af4396e0441b7d292045cf78bc22187eec981e5d6fe2ebd0794f975a"), byteorder="big", signed=False))


if __name__ == '__main__':
    unittest.main()