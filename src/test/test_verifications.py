#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde
import unittest
from algos.verifications import initialize_gpg, verify_signature_gpg, close_gpg, verification_of_the_public_election_key_with_zk_proof, verification_of_a_ballot_entry, verify_signature_rsa
from algos.verifications import verification_of_a_zk_proof_of_shuffle, independent_generators_for_ec_groups_of_prime_order, verification_of_ballot_decrytion, decoding_of_a_decrypted_ballot
from algos.secp256k1 import Curve


class VerificationOfTokenAuthorisationTestClass(unittest.TestCase):
    def test_valid_auth(self):
        publicKeyString = """
mDMEZGfJGBYJKwYBBAHaRw8BAQdAwuYytOtSvtHCpXyJj3AO10XJ/ol69GfTYAFI
4elTvUO0BGNocmmImQQTFgoAQRYhBHUZTq9G8yt84tsEIJoCUoGTrlq9BQJkZ8kY
AhsDBQkDwzgIBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEJoCUoGTrlq9
J+QBAMALYXS9xLsgQHuobhm62eQOYX4HYDzv7Qjc/xXLAYHvAQCdM+i/pl1VaaVw
TLEoc5kgWjIDq/Wzj9cjPZUdmopmA7g4BGRnyRgSCisGAQQBl1UBBQEBB0DbyZph
+n9ez7K2yetz5dJil1UcKWY1a15SksG9d4Q3dAMBCAeIfgQYFgoAJhYhBHUZTq9G
8yt84tsEIJoCUoGTrlq9BQJkZ8kYAhsMBQkDwzgIAAoJEJoCUoGTrlq988wBAJwu
MulKnfT/2OVJzMEZPeBmhOrkh4m43kThwj/XFkyDAQCST7Fy0DC2/bJO7zHil2hP
n6Lx2qtwyegzPMKRE36JCw==
=5fBt
"""
        gpg = initialize_gpg([publicKeyString], path="gpg_tmp1")
        # This is normalized String, not fingerprint
        # TODO sign actual fingerprint
        fingerprint = "REVOCATION_TOKEN{ELECTION=electionId,VOTERS=[voter0]}"
        sign = "iHUEABYKAB0WIQR1GU6vRvMrfOLbBCCaAlKBk65avQUCZGnqfQAKCRCaAlKBk65avT4bAQCWqpN5Mp1K1/AH1o8tp5lYqbIzClXeu/pGib+031n6kwD+MR6Iwu1r6QhgK0nabP+ko+/nOStIGZNu7QKiwTUBnAU="
        self.assertTrue(verify_signature_gpg(fingerprint, sign, gpg)[0])

    def test_invalid_token(self):
        publicKeyString = '''
mDMEZGfJGBYJKwYBBAHaRw8BAQdAwuYytOtSvtHCpXyJj3AO10XJ/ol69GfTYAFI
4elTvUO0BGNocmmImQQTFgoAQRYhBHUZTq9G8yt84tsEIJoCUoGTrlq9BQJkZ8kY
AhsDBQkDwzgIBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEJoCUoGTrlq9
J+QBAMALYXS9xLsgQHuobhm62eQOYX4HYDzv7Qjc/xXLAYHvAQCdM+i/pl1VaaVw
TLEoc5kgWjIDq/Wzj9cjPZUdmopmA7g4BGRnyRgSCisGAQQBl1UBBQEBB0DbyZph
+n9ez7K2yetz5dJil1UcKWY1a15SksG9d4Q3dAMBCAeIfgQYFgoAJhYhBHUZTq9G
8yt84tsEIJoCUoGTrlq9BQJkZ8kYAhsMBQkDwzgIAAoJEJoCUoGTrlq988wBAJwu
MulKnfT/2OVJzMEZPeBmhOrkh4m43kThwj/XFkyDAQCST7Fy0DC2/bJO7zHil2hP
n6Lx2qtwyegzPMKRE36JCw==
=5fBt
'''
        gpg = initialize_gpg([publicKeyString], path="gpg_tmp2")
        # This is normalized String, not fingerprint
        # TODO sign actual fingerprint
        fingerprint = "REVOCATION_TOKEN{ELECTION=electionId,VOTERS=[voter0]}"
        sign = "iHUEABYKAB0WIQR1GU6vRvMrfOLbBCCaAlKBk65avQUCZGtV2AAKCRCaAlKBk65avSPDAQDNNg0xVjuJCq/WpFNinAkwkeyToA9NEJcIrdNjbzaIOAD+PDJFj80AyBVABDA904Gj/Vg55V7i3EZPze1CKQ4DAAw="
        self.assertFalse(verify_signature_gpg(fingerprint, sign, gpg)[0])

    def test_invalid_key(self):
        publicKeyString = '''
mDMEZGtccBYJKwYBBAHaRw8BAQdA1Jq/oqzxLIM1FVqXO85+DQ24r23L440ydokK
Ax1mL2O0BnNlY29uZIiZBBMWCgBBFiEEgY9oaY4+9Yn7ajbA8dR2aYD31zsFAmRr
XHACGwMFCQPDmTAFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ8dR2aYD3
1zvZjAEAv0IfjJA3DX45MmEkyIoYxXqSZyaxJfJoO0VE0cGIyx0BAO68WlUr6F1D
eSFoP3lr6z6gbNI2USHEGwxs8aO1nRgGuDgEZGtccBIKKwYBBAGXVQEFAQEHQC8H
Nb/hSChPqINp1oAc6aMTM7cuJjDZDLYHt015Mug4AwEIB4h+BBgWCgAmFiEEgY9o
aY4+9Yn7ajbA8dR2aYD31zsFAmRrXHACGwwFCQPDmTAACgkQ8dR2aYD31ztTpQEA
6sqEP/aCVxykHTiKC6C8850A5CqIEeqCgm3oAkyQrc0A/RdpwzeyfaBL8ysRSste
kzU1hGF/R7orkt488V/+BywO
=m+La
'''
        gpg = initialize_gpg([publicKeyString], path="gpg_tmp3")
        # This is normalized String, not fingerprint
        # TODO sign actual fingerprint
        fingerprint = "REVOCATION_TOKEN{ELECTION=electionId,VOTERS=[voter0]}"
        sign = "iHUEABYKAB0WIQR1GU6vRvMrfOLbBCCaAlKBk65avQUCZGnqfQAKCRCaAlKBk65avT4bAQCWqpN5Mp1K1/AH1o8tp5lYqbIzClXeu/pGib+031n6kwD+MR6Iwu1r6QhgK0nabP+ko+/nOStIGZNu7QKiwTUBnAU="
        self.assertFalse(verify_signature_gpg(fingerprint, sign, gpg)[0])

    def tearDown(self):
        close_gpg("gpg_tmp1")
        close_gpg("gpg_tmp2")
        close_gpg("gpg_tmp3")


class VerificationOfThePublicElectionKeyWithZKProofTestClass(unittest.TestCase):
    """
    unittest.TestCase of the verification of the public election key with ZK-proof (algorithm 8)
    """
    def test_from_doc(self):
        pk = bytearray.fromhex("03403091F3E81EE0E125FC33614DBA1ADBA569A3F7C05F9B36587054151508D490")
        c = 62327941685486825449134997199289669684207465147565480140532634650865472277154
        f = 51962687162358528709409258407636465178388247306669152965012697266119803118583

        self.assertEqual(True, verification_of_the_public_election_key_with_zk_proof(pk, c, f))

    def test_fail(self):
        pk = bytearray.fromhex("03403091F3E81EE0E125FC33614DBA1ADBA569A3F7C05F9B36587054151508D490")
        c = 62327941685486825449134997199289669684207465147565480140532634650865472277154
        f = 51962687162358528709408258407636465178388247306669152965012697266119803118583

        self.assertEqual(False, verification_of_the_public_election_key_with_zk_proof(pk, c, f))


class VerificationOfABallotEntryTestClass(unittest.TestCase):
    """
    unittest.TestCase of the verification of a ballot entry
    """
    def test_from_doc(self):
        pk = bytearray.fromhex("0323863C357CF3CDFF282CB747CB23F94CCC9173B795412E773F908CC8B81AA354")
        z = bytearray.fromhex("03D0D99E7CB4330B6037CFC64139298DD46417D1B44781A0381CB0313F26541870")
        private_credentials = (71296294066727390017142573272499110353651332475311228044572225570162122199458, 93740793070444965834350731700811288291897877020039084234269069666765422852427)
        encrypted_coins = [
            (55667612424127479016959768115758309554487545206887638059563287587298269617180, 76750441957428754273366458063623429821774646529073833195390073367592941723801),
            (87497191161142043606355252810633074518695312428888729285556397934908609418119, 100800068275679310663391149138368437347267201966121012311937023355457387545611)
        ]
        encrypted_choices = [
            (bytearray.fromhex("0296EA334615B205F2B75AED751586FBFBFF794B4F96780146E55A11D3ED5447BF"),
                bytearray.fromhex("0237A9A3B7738311C6F36D954A8CAB89A697FD8AEF38676D732EC44FB978269F26")),
            (bytearray.fromhex("029701753C446CCAF47A37D6AC28107AB026DD914D77989D36CF0F9319D161297F"),
                bytearray.fromhex("03793ED5EE4A3CD89BD74C4AE44E88614845B72702FCA623F54EEDE5821F7F453C"))
        ]

        self.assertEqual(True, verification_of_a_ballot_entry(pk, "a", z, encrypted_choices, private_credentials, encrypted_coins))


class VerificationOfAZKProofOfShuffleTestClass(unittest.TestCase):
    """
    unittest.TestCase of the verification of the shuffle
    """
    def test_multikey_commitments(self):
        curve = Curve()
        h1 = independent_generators_for_ec_groups_of_prime_order(curve.p, curve.a, curve.b, bytearray("Polyas".encode("utf-8")), 10 + 1)
        self.assertEqual(h1.compress_as_bytearray(), bytearray.fromhex("03F08FCB284F32B737E0529840334D481E055AD6AFA18AB91A3B02939EB19EB8DD"))

        h2 = independent_generators_for_ec_groups_of_prime_order(curve.p, curve.a, curve.b, bytearray("Polyas".encode("utf-8")), 10 + 2)
        self.assertEqual(h2.compress_as_bytearray(), bytearray.fromhex("034A90A88BD2D3A92D7A29D19135F25536516D46FE4B8776C74B9E26D834FDA588"))

        h3 = independent_generators_for_ec_groups_of_prime_order(curve.p, curve.a, curve.b, bytearray("Polyas".encode("utf-8")), 10 + 3)
        self.assertEqual(h3.compress_as_bytearray(), bytearray.fromhex("0365DB947FD33BE257599D9E0BD1513E6F7B3BBE6C9008382E22F4B527D3A39299"))

        h = independent_generators_for_ec_groups_of_prime_order(curve.p, curve.a, curve.b, bytearray("Polyas".encode("utf-8")), 10)
        self.assertEqual(h.compress_as_bytearray(), bytearray.fromhex("02549196ea21197151c73c3c9bda1f12da2bbea99f2efb0dd8bc235a9ced37ecb9"))

    def test_from_doc(self):
        pk = bytearray.fromhex("0300000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63")

        inputEs = [

            [
                (bytearray.fromhex("0214C8ED687A03590A5DFF16207636B75641E4265077C0C8546FF820188662EB5F"),
                    bytearray.fromhex("03E08BA84715A5CC14B27895F7A42194933CF7D9B71101F99CDEB0800399F02C20")),

                (bytearray.fromhex("032392DF7D3B7BDFFF9A7ACC599E20D4C435755B4EF73C458900B0928B34864DAE"),
                    bytearray.fromhex("02234DBE74A1D90B6D7EE8A376958347028B07A71DEB69FD203692AA9CCE86865A")),

                (bytearray.fromhex("02B4EA4738B32421826F1F87A4712372059F4DEDBA136155BAAEA76FDA77FD1B77"),
                    bytearray.fromhex("03577F6FEFC44A662ACA61A09A3C0D6D57B5BBAE5D54DEC8843F1A3CBC5096B557"))
            ],

            [
                (bytearray.fromhex("0203B5E69A3B368C16351D2AFB94135A13C3E3E325F0D04612F31FC8E79CA8AF23"),
                    bytearray.fromhex("020833D683DC989F9F43CC5C6229A01D8036E4B0EF980E9B3A5035D4267E85B328")),

                (bytearray.fromhex("02305032260DE32A5C1C2E38AB18229AD1A52540A1333E265EEDA3060BC84EDD10"),
                    bytearray.fromhex("024FC453BDF7159175F8A647DDD81E124A9BC988AFDEAE4F578A0A0F1C7AFD01C4")),

                (bytearray.fromhex("029EE3273853C61A09EE816D93220D3BB268E843B84516DB3E19108FEC719E9B29"),
                    bytearray.fromhex("036AB3656C933BF8A6C07A1031FBB502250CB966A25BA1A0E668718D20DCC594CC"))
            ],

            [
                (bytearray.fromhex("020D5725F57B7B90DC5D16A45C121F8B8ACF2981490E5BF7756F78E1FFC9010364"),
                    bytearray.fromhex("0338E08940BC3F3681DB354930ACEB98C4EBB7C7796225DD274D5E9B828A18FDC8")),

                (bytearray.fromhex("03AE8B4B0DC1A0DCE73DC5BE8F8F45B76D349FA77A22109D0647890B035DF1C18D"),
                    bytearray.fromhex("025718470F1BE2A75653CD608CF2999E5A1F7B57778C76DB5B74AED2084C87B624")),

                (bytearray.fromhex("02811B7C71E2C5EC448FB9E937FB97501E2DB95B080C0FC3639EC25FBE06BB859F"),
                    bytearray.fromhex("038CCFC46E348B0A2D5FF4DB1EFA4E4388D706D133B13B35A1D0D582B50A2B4495"))
            ],

            [
                (bytearray.fromhex("02DC464302FBE1CE58ECE95B1A40B4FD99C190456844E17D62AA51801C246668F2"),
                    bytearray.fromhex("033AC4F52C385066CBBBC04BDC87D87232F58B02B98F7F4661C766114FDD950A65")),

                (bytearray.fromhex("032C50FD2FB9811BC47A76D1478E13A3E5B4631AF8B97D3EB32347FB597FC0D72C"),
                    bytearray.fromhex("02FFA0CFD2B1E7CA591BFA8E33AB9EB54005A773DF5E0A96371DF3ADCDDC58D965")),

                (bytearray.fromhex("023460FDA0AF0D22DFF6F18C2CDD7A8325EB9EA28C177D83CB2BB2CD7FE10ADE66"),
                    bytearray.fromhex("03ED73B8D97CEED2B56924D91A1C48330DA0669CA2323463C4EC211429704E2C2D"))
            ],

            [
                (bytearray.fromhex("024622D7BD63EA32760775DEA4F70531445C22BBFD4E4BCDB9B65E93E728916DF1"),
                    bytearray.fromhex("03D21229F0D579ACBDCBA52A69D452FFA15BE431AB44E053F8C045690643AFEEA4")),

                (bytearray.fromhex("0292B9CE0CEA817BDA811CD1B0687F18EEA410FF4AED585E57F2CB2772AEB12089"),
                    bytearray.fromhex("03215C6F22892AF7AFF3D07D5945C33E0ECA2A71114E7735182E0A426925A3B943")),

                (bytearray.fromhex("039B21A650670E8C9266A8B9951CA667C417ABF10D872FC518295CEF251365CC51"),
                    bytearray.fromhex("0341B2AE82C303AA11EB36F888C0EE84A3CB45EB3CC2EA2A9892453876E1A63732"))
            ]

        ]

        outputEs = [

            [
                (bytearray.fromhex("02456DE1179DB1B71A99277A3DE50F4AABB8F067E919394094F1796975D61C8241"),
                    bytearray.fromhex("0204B89C49C36D914A6345FC891B2D2C218CD6EC92618246D6CBCEDC8B3915E7B3")),

                (bytearray.fromhex("0209C4E8F415C4BD201783206EACBF2350D621DDB54AFBBE530FA4FA01618DF539"),
                    bytearray.fromhex("02BA2F9D6BA01F64B36DE7BF8C0B6FFB54C3E4E8E3A208353827F415701C07E8F8")),

                (bytearray.fromhex("0369715046EA5CA8A5BB300ADDC7FA7DC46A7F3CDBB5F0E3F8DB91D018B8C9C973"),
                    bytearray.fromhex("031ED897C05609D58C216BA04B7C59E914CCA2CF260F18E9C9E61831DEE9FBB47F"))
            ],

            [
                (bytearray.fromhex("020C1C7A58906A5E7FEA11D8499F3FC6807F8A9214E82D0448E7D1128BC7BA216F"),
                    bytearray.fromhex("03BC78094A4296878A77FE026D689FD10FD5DE3005FF512BA19E599AB9EE51D46B")),

                (bytearray.fromhex("036CD0CC7159AE847A80BFCC26088F919EA808343CC631E6B7D17534AB9364A1C2"),
                    bytearray.fromhex("036721AB124B5E691355E269ED85EC7225DF2F1E2689A3904E63CDB99557DE590E")),

                (bytearray.fromhex("02813373C27103E17FD43EBFBEF79CA7BA31F3F17E707B42362B7848063D10A271"),
                    bytearray.fromhex("032C9A98CDEB02444DF56B09553C36FCBDB9B470B1A39518EAFD64018F35999262"))
            ],

            [
                (bytearray.fromhex("03AB7BE97B4A7B879B9F893C03AA7B477BF34785F80FC967EC75144882BB8EA72C"),
                    bytearray.fromhex("02A641223FC94FEE1E0E7F24E1C1B475BA45F91364984D94F3FB529812C26EBC34")),

                (bytearray.fromhex("02F7340EAA4299973AB27231C27E53B90B913554F03721BA06E3C344DE72F42A0C"),
                    bytearray.fromhex("02128077E42835DB0B2A992BA9A3415481C2EC1A9350C07674111CFFD3528348C6")),

                (bytearray.fromhex("0372B6FAD5684760BA7105A449112D78EF4F60CC80752B33CCB79852AFF36BEAC7"),
                    bytearray.fromhex("02A284A3A53AE803E684F5E903DB687354F7C21CFA51C304691C1D5DE0394883F9"))
            ],

            [
                (bytearray.fromhex("0279045EEC54A7C574B0475932ACA3F7C5022DB5DA63CCF59486037E87FFF5FC13"),
                    bytearray.fromhex("0339C7B1DAFF747CA0BB51199909C51EE1A2A8D85678CFFCC10834CA850F923BA5")),

                (bytearray.fromhex("0287DBE4AC3C675718332715FD10B8A65F75A79769F664B8C9EF7138BE27DCEC3D"),
                    bytearray.fromhex("022F8D43DEA945BC03299F4285CDE8FF028EAA7352826490F1DE2C8A3E7200541F")),

                (bytearray.fromhex("03A06D4592A73B1211C0E7616C502CC1A851CE869F6474A24869B5D692D022BE83"),
                    bytearray.fromhex("03F43A46AC5B017F8C090B1BB19FFBF91FC0BBD635980BE36028A07C9A78AE73CC"))
            ],

            [
                (bytearray.fromhex("033BCD27079C93D3A0D5489EA4E97A37AD2C0BB993AB03828F15AFDCE86A09D1EE"),
                    bytearray.fromhex("02E20CC62C67B3D7ACA45D35F0982ADB2AFE00B211491E2BEE57FF839E2AA77891")),

                (bytearray.fromhex("0227403C521B76EF97C257042F95B67EF0EBCF38CBEF6147ED384A696D09B3B4F1"),
                    bytearray.fromhex("02055EF3DF1BB93420BAC356B7E4FFF281F996E06955A67ED8E7A81D0F2E902030")),

                (bytearray.fromhex("03B4BF902DF1EB8BF992E1FCB7DAFBFA52DF056869879A4EFA2EE617224B2028AA"),
                    bytearray.fromhex("02C5945ED05DD243D456DBD883BE62062CE160B7947C1931B16E9A742A643CA9A7"))
            ]

        ]

        c = [
            bytearray.fromhex("03063CA66F8C0ECEAAB8236BA467F3D817710FBF45792A6AC31DF6AF4293F3F5FC"),
            bytearray.fromhex("038B87D18C31424A6C217FF70AA58F5B5682093DE6BCC7073E66DAE1BF6B32BE0D"),
            bytearray.fromhex("038C81504B353A3DA542AB71B2D9F303053305E675C2D6D09B59692C72C79BC6C7"),
            bytearray.fromhex("03EBE3705F74AF1E0E0E5CEF5C55A0C4768EF94B656799CF81A7D3A7664F01A1E7"),
            bytearray.fromhex("03CCAB079B02DFED7DB56621060FBF2A795E39D4CDEBA4A9B7799AB92191484DA5")
        ]

        cHat = [
            bytearray.fromhex("02015DCE2FFFFCA395A6E62C0F2661BF4F4D17AEDBAD90B1CD3C111B7E9FEF0DCE"),
            bytearray.fromhex("03560966D35CF68F89F81E233D329F1C64E8F5991D270CEF49843BD00E6DC5CBF8"),
            bytearray.fromhex("027718D13F8E0AC62E269507BB3FBDACDDFF11D29E6971C64F2BFF9535735FF5CE"),
            bytearray.fromhex("033749E1628EEB14EE6AD370BD47F430020A3E7CD77A3D2CF20F5177EE79FDA462"),
            bytearray.fromhex("03EE78C0CD5E0320E8BC342C420D873802ED1FF2AE8D9D4FC165B405821394E82C")
        ]

        t1 = bytearray.fromhex("035C091CBE9D77D0030FE3584CC20DF2C1DB0621F07E3C16600981C9A806C39E15")
        t2 = bytearray.fromhex("0211DA61A861A0B7AF9D3A77022EB55B511D4B07F18D271B6C61ADFF155BD419B1")
        t3 = bytearray.fromhex("023D82EA9E9ADC647E699EF1901BCBB89B7D587DAF328BA354B100020245C1E6E7")

        t4 = [
            (bytearray.fromhex("03C0CE5B3CB78C48072687ADB95A74928065C5E02197E8FA84CB82FFF5F32B56C2"),
                bytearray.fromhex("03919EDA2E6275ABA58260D4B0A260E8E6A2D9BB99486CFB1BAB41C56400FFF473")),

            (bytearray.fromhex("030DE4191A9F916DDA2BC0F89B6CF91FB86504A937116F0F5390F947CB19C9B2DF"),
                bytearray.fromhex("039681898C617F1D9304B1B3103C009CDF98B6509A768C89B3DC1D6D97102414AD")),

            (bytearray.fromhex("022204EADACC736A723A774F2F852DACE0FE2063A35B6DC73DB02CEE9C6913338E"),
                bytearray.fromhex("031E12721D6AB8E4789ABD2EB074BCBEE4B931112B23F45C5CBBA2040DF0CDBAFE"))

        ]

        tHat = [
            bytearray.fromhex("02A6B5848F4C8A548DEC32CF69DD62102A0229A91754833011ABEDF7C37CAD0B35"),
            bytearray.fromhex("03AFFAFC3E79F3F0D5E167D28CD07E32FB2A2013E3C4E10228A1CF93EC01191D24"),
            bytearray.fromhex("02D4CC74684CAC1AAF3B097202A53D6C95E56063A9FAACFB83880A9275ECF1DB5F"),
            bytearray.fromhex("0247C0DAF54B4BBB57CD02055F669B6C3AF8A2772B7A4D724B028F80CC85F7905F"),
            bytearray.fromhex("02BD163CFCF9F8F5220D97C2CAEED5ED6F8631FA440EDFE62EF42A1130A10D60BF")
        ]

        s1 = 69140316880887008429299433409534792696848419093216873680551974897144887159610
        s2 = 53131180115819471603649661885837848951867892970603491894778242682301254803439
        s3 = 66545885786812536207434432222640477995631070643429160379121299767828529923058

        s4 = [
            49234149869250594959301514806927880761621594652382929864916536478567293576403,
            44119365916638103229779040146256231483538164307118362944358852857821116505672,
            86462011021256247510587356706438016595527168971353930254607186965833238087671
        ]

        sHat = [
            87579523046122018987817401009461204121160246014860600118901358882259284285635,
            56314690457336236085857831679824894426738981904694725128459520767201510302300,
            25753679853418879190896890932270665331640358030057655550457509094727662595142,
            63915129513865911136597604340649908830039343581913211436624902429643358348225,
            69854345023046456752350915483794001845993865628180922659193497065328728076315
        ]

        sPrime = [
            72366274572044528102669983191011032953991484588099121769246644882582908886523,
            17352610575896663921431335332316518805152884681769238935143288047873148108374,
            56595689515425780322167150059926269989757326187503888391850755958939583506650,
            93208000741043741183848971908195921861581255731370504280744340908021922517310,
            14357102550628836472011521008020057134171259373041892981299923206753076424152
        ]

        zkproof = (
            c, cHat, t1, t2, t3, t4, tHat, s1, s2, s3, s4, sHat, sPrime
        )

        self.assertEqual(True, verification_of_a_zk_proof_of_shuffle(pk, inputEs, outputEs, zkproof, test=True))


class VerificationOfBallotDecryptionTestClass(unittest.TestCase):
    """
    unittest.TestCase of the verification of ballot decryption
    """
    def test_from_doc(self):
        ciphertexts = [
            (bytearray.fromhex("03B467D17D26AE0A29034C698A15F8E50C7DD17D43F2F088091479B8C0B9CFFC60"),
                bytearray.fromhex("037EA63D9BB3E1FE8AB74DB33E60DCA353878B9169D01585D53F59A30DB7029C16"))
        ]

        message = bytearray.fromhex("010601020204010000000000000000")
        pk = bytearray.fromhex("03403091F3E81EE0E125FC33614DBA1ADBA569A3F7C05F9B36587054151508D490")

        proofs = [
            [
                bytearray.fromhex("0220BF3495CDBDFCE2D10EB330AB72A56FC67B7D12BDB9270BB18D896089787FC6"),
                (
                    86855984657246342025261681749033304437687691935040825490016247057942046977271,
                    97749087812374827457568318313550679277605194827170221699264620792657623830605
                )
            ]
        ]

        self.assertTrue(verification_of_ballot_decrytion(pk, ciphertexts, message, proofs))

    def test_from_boarddescriptions(self):
        ciphertexts = [
            (bytearray.fromhex("02b77b09bf11723c4bd157bfbe74d37f4f155628d1b0b7d6a1b46e6a5bc3a14f28"),
                bytearray.fromhex("0230abd307979beab9b2990cb736a573619b413f87f54a5f53386bcf2618cd0e62"))
        ]

        message = bytearray.fromhex("0000010000000000000000000000000000000000")
        pk = bytearray.fromhex("0207914e652f3af62f8a69b48c204309db1111d94ca7028702e09c878d37d9e824")

        proofs = [
            [
                bytearray.fromhex("03d68044a96c78a1f8410f78daa7d041dab644f615330707bb1e72f94970d2ddc6"),
                (
                    26694133837703613987199985328597300962169484650485475882041600134260079549228,
                    49966421882536224498594781377295512255564243513747826326881423196708679703657
                )
            ]
        ]

        self.assertTrue(verification_of_ballot_decrytion(pk, ciphertexts, message, proofs))


class DecodingOfADecryptedBallotTestClass(unittest.TestCase):
    """
    unittest.TestCase for the decoding of a decrypted ballot (algorithm 9)
    """
    def test_from_doc(self):
        content = bytearray.fromhex("01070208020901")
        res = decoding_of_a_decrypted_ballot(content)
        self.assertEqual(res[0][0], 0x07)
        self.assertEqual(res[0][1], 0)
        self.assertEqual(res[0][2][0], 2)
        self.assertEqual(res[0][2][1], 8)
        self.assertEqual(res[0][3][0], 1)
        self.assertEqual(res[0][3][1], 9)


class VerificationOfReceitTestClass(unittest.TestCase):
    def testValid(self):
        publicKey = '''
        30820122300d06092a864886f70d01010105000382010f003082010a0282010100a52865923e9a08c8e58c0beacd3f40391f980b7db7a87c626d68dbf2a2a2
        8a848402e5adc7ae7d3afef34b697bcf26e5c29b3be55850f2c7a308d90573d6b3788339104fc7579b07b483ccafa11f12ad123f6eaeb3a64a5cdc3f944ed6
        13d5ad1bb6f8cbb704682d16391f731fac0c87dfe84859c9c9fd690a57cbe7a7bdf3a69d3e8457a1afd88112bf44538b6a04809b3e61ef9608c24ef1f02d67
        96e73bbeff49efca7a9cf443e36791bce307323d1a05f7fd8d8697b820f632eb50b19a2b4f20c958e193ec80b269e4a1b322bbd2a9d27ba91e7e1f5440bf94
        4cdb1658f5d6d612a0b1d838cbbe19640fd4c5d967b03b95c388910c6ce0c3ecd9340af3f90203010001
        '''.replace("\n", "").replace(" ", "")
        sign = '''
        529f3e8c7d1f0e2c8061526d8e1d8000c24ab60b32b3bda0ce959788483f977fb12da70ccb7ac154a698ef925cf7ca52e142f8eb22d23e5ccd42b63da22723
        0bf886b13211f5c1f618a946a64f8566fd36849b46a156d4a35288204fd7b22e15fcdce8884b5d6e5c69b07ca271332ba14eced079402c735db642b82ae747
        8fe2efe849d8c50ba11b7d6985486607a54ea42c6394dc2060ac58cfa9c69cc750816dad43fb74d113ab7bc014e619649688fdbf96a29c894fa2cfc5d2bac8
        b897d0c8dbb3b79e5c17a90913dcb4ba583ea90e706891d38278745c1b4856f88d045c38b840d4fd427291187c250b2ed7bc846fa25440e98d3e9832f2047e
        52bc5207 '''.replace("\n", "").replace(" ", "")
        fingerprint = "91dd5f592932c7c681f20310c801e7ea935f116527b65ce6524f14c6ad2f9dac"
        self.assertTrue(verify_signature_rsa(fingerprint, sign, publicKey))

    def testInvalidFingerpint(self):
        publicKey = '''
        30820122300d06092a864886f70d01010105000382010f003082010a0282010100a52865923e9a08c8e58c0beacd3f40391f980b7db7a87c626d68dbf2a2a2
        8a848402e5adc7ae7d3afef34b697bcf26e5c29b3be55850f2c7a308d90573d6b3788339104fc7579b07b483ccafa11f12ad123f6eaeb3a64a5cdc3f944ed6
        13d5ad1bb6f8cbb704682d16391f731fac0c87dfe84859c9c9fd690a57cbe7a7bdf3a69d3e8457a1afd88112bf44538b6a04809b3e61ef9608c24ef1f02d67
        96e73bbeff49efca7a9cf443e36791bce307323d1a05f7fd8d8697b820f632eb50b19a2b4f20c958e193ec80b269e4a1b322bbd2a9d27ba91e7e1f5440bf94
        4cdb1658f5d6d612a0b1d838cbbe19640fd4c5d967b03b95c388910c6ce0c3ecd9340af3f90203010001
        '''.replace("\n", "").replace(" ", "")
        sign = '''
        529f3e8c7d1f0e2c8061526d8e1d8000c24ab60b32b3bda0ce959788483f977fb12da70ccb7ac154a698ef925cf7ca52e142f8eb22d23e5ccd42b63da227230
        bf886b13211f5c1f618a946a64f8566fd36849b46a156d4a35288204fd7b22e15fcdce8884b5d6e5c69b07ca271332ba14eced079402c735db642b82ae7478f
        e2efe849d8c50ba11b7d6985486607a54ea42c6394dc2060ac58cfa9c69cc750816dad43fb74d113ab7bc014e619649688fdbf96a29c894fa2cfc5d2bac8b89
        7d0c8dbb3b79e5c17a90913dcb4ba583ea90e706891d38278745c1b4856f88d045c38b840d4fd427291187c250b2ed7bc846fa25440e98d3e9832f2047e52bc
        5207
        '''.replace("\n", "").replace(" ", "")
        fingerprint = "01dd5f592932c7c681f20310c801e7ea935f116527b65ce6524f14c6ad2f9dac"
        self.assertFalse(verify_signature_rsa(fingerprint, sign, publicKey))
