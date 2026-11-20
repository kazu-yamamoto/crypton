{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Hedged signatures for DSA and ECDSA, and the deterministic DSA of
-- RFC 6979 that the hedged nonce is built on.
module PubKey.HedgedSpec (spec) where

import qualified Crypto.ECC as ECC
import Crypto.Error (throwCryptoError)
import Crypto.Hash
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSAOld
import qualified Crypto.PubKey.ECC.Generate as ECCG
import qualified Crypto.PubKey.ECC.Types as ECCT
import qualified Crypto.PubKey.ECDSA as ECDSA
import Crypto.Random (drgNewTest, withDRG)
import Data.Proxy (Proxy (..))

import Imports

-- | The hash a vector names.
data H = H1 | H224 | H256 | H384 | H512
    deriving (Show)

-- | RFC 6979 A.2.1 and A.2.2: a key, and for each hash and message the
-- nonce and the signature.
data Vector
    = Vector String DSA.PrivateKey [(H, ByteString, Integer, Integer, Integer)]

dsa1024 :: Vector
dsa1024 =
    Vector
        "dsa1024"
        ( DSA.PrivateKey
            ( DSA.Params
                0x86f5ca03dcfeb225063ff830a0c769b9dd9d6153ad91d7ce27f787c43278b447e6533b86b18bed6e8a48b784a14c252c5be0dbf60b86d6385bd2f12fb763ed8873abfd3f5ba2e0a8c0a59082eac056935e529daf7c610467899c77adedfc846c881870b7b19b2b58f9be0521a17002e3bdd6b86685ee90b3d9a1b02b782b1779
                0x07b0f92546150b62514bb771e2a0c0ce387f03bda6c56b505209ff25fd3c133d89bbcd97e904e09114d9a7defdeadfc9078ea544d2e401aeecc40bb9fbbf78fd87995a10a1c27cb7789b594ba7efb5c4326a9fe59a070e136db77175464adca417be5dce2f40d10a46a3a3943f26ab7fd9c0398ff8c76ee0a56826a8a88f1dbd
                0x996f967f6c8e388d9e28d01e205fba957a5698b1
            )
            0x411602cb19a6ccc34494d79d98ef1e7ed5af25f7
        )
        [
            ( H1
            , "sample"
            , 0x7bdb6b0ff756e1bb5d53583ef979082f9ad5bd5b
            , 0x2e1a0c2562b2912caaf89186fb0f42001585da55
            , 0x29efb6b0aff2d7a68eb70ca313022253b9a88df5
            )
        ,
            ( H224
            , "sample"
            , 0x562097c06782d60c3037ba7be104774344687649
            , 0x4bc3b686aea70145856814a6f1bb53346f02101e
            , 0x410697b92295d994d21edd2f4ada85566f6f94c1
            )
        ,
            ( H256
            , "sample"
            , 0x519ba0546d0c39202a7d34d7dfa5e760b318bcfb
            , 0x81f2f5850be5bc123c43f71a3033e9384611c545
            , 0x4cdd914b65eb6c66a8aaad27299bee6b035f5e89
            )
        ,
            ( H384
            , "sample"
            , 0x95897cd7bbb944aa932dbc579c1c09eb6fcfc595
            , 0x07f2108557ee0e3921bc1774f1ca9b410b4ce65a
            , 0x54df70456c86fac10fab47c1949ab83f2c6f7595
            )
        ,
            ( H512
            , "sample"
            , 0x09ece7ca27d0f5a4dd4e556c9df1d21d28104f8b
            , 0x16c3491f9b8c3fbbdd5e7a7b667057f0d8ee8e1b
            , 0x02c36a127a7b89edbb72e4ffbc71dabc7d4fc69c
            )
        ,
            ( H1
            , "test"
            , 0x5c842df4f9e344ee09f056838b42c7a17f4a6433
            , 0x42ab2052fd43e123f0607f115052a67dcd9c5c77
            , 0x183916b0230d45b9931491d4c6b0bd2fb4aaf088
            )
        ,
            ( H224
            , "test"
            , 0x4598b8efc1a53bc8aecd58d1abbb0c0c71e67297
            , 0x6868e9964e36c1689f6037f91f28d5f2c30610f2
            , 0x49cec3acdc83018c5bd2674ecaad35b8cd22940f
            )
        ,
            ( H256
            , "test"
            , 0x5a67592e8128e03a417b0484410fb72c0b630e1a
            , 0x22518c127299b0f6fdc9872b282b9e70d0790812
            , 0x6837ec18f150d55de95b5e29be7af5d01e4fe160
            )
        ,
            ( H384
            , "test"
            , 0x220156b761f6ca5e6c9f1b9cf9c24be25f98cd89
            , 0x854cf929b58d73c3cbfdc421e8d5430cd6db5e66
            , 0x91d0e0f53e22f898d158380676a871a157cda622
            )
        ,
            ( H512
            , "test"
            , 0x65d2c2eeb175e370f28c75bfcdc028d22c7dbe9c
            , 0x8ea47e475ba8ac6f2d821da3bd212d11a3deb9a0
            , 0x7c670c7ad72b6c050c109e1790008097125433e8
            )
        ]

dsa2048 :: Vector
dsa2048 =
    Vector
        "dsa2048"
        ( DSA.PrivateKey
            ( DSA.Params
                0x9db6fb5951b66bb6fe1e140f1d2ce5502374161fd6538df1648218642f0b5c48c8f7a41aadfa187324b87674fa1822b00f1ecf8136943d7c55757264e5a1a44ffe012e9936e00c1d3e9310b01c7d179805d3058b2a9f4bb6f9716bfe6117c6b5b3cc4d9be341104ad4a80ad6c94e005f4b993e14f091eb51743bf33050c38de235567e1b34c3d6a5c0ceaa1a0f368213c3d19843d0b4b09dcb9fc72d39c8de41f1bf14d4bb4563ca28371621cad3324b6a2d392145bebfac748805236f5ca2fe92b871cd8f9c36d3292b5509ca8caa77a2adfc7bfd77dda6f71125a7456fea153e433256a2261c6a06ed3693797e7995fad5aabbcfbe3eda2741e375404ae25b
                0x5c7ff6b06f8f143fe8288433493e4769c4d988ace5be25a0e24809670716c613d7b0cee6932f8faa7c44d2cb24523da53fbe4f6ec3595892d1aa58c4328a06c46a15662e7eaa703a1decf8bbb2d05dbe2eb956c142a338661d10461c0d135472085057f3494309ffa73c611f78b32adbb5740c361c9f35be90997db2014e2ef5aa61782f52abeb8bd6432c4dd097bc5423b285dafb60dc364e8161f4a2a35aca3a10b1c4d203cc76a470a33afdcbdd92959859abd8b56e1725252d78eac66e71ba9ae3f1dd2487199874393cd4d832186800654760e1e34c09e4d155179f9ec0dc4473f996bdce6eed1cabed8b6f116f7ad9cf505df0f998e34ab27514b0ffe7
                0xf2c3119374ce76c9356990b465374a17f23f9ed35089bd969f61c6dde9998c1f
            )
            0x69c7548c21d0dfea6b9a51c9ead4e27c33d3b3f180316e5bcab92c933f0e4dbc
        )
        [
            ( H1
            , "sample"
            , 0x888fa6f7738a41bdc9846466abdb8174c0338250ae50ce955ca16230f9cbd53e
            , 0x3a1b2dbd7489d6ed7e608fd036c83af396e290dbd602408e8677daabd6e7445a
            , 0xd26fcba19fa3e3058ffc02ca1596cdbb6e0d20cb37b06054f7e36ded0cdbbccf
            )
        ,
            ( H224
            , "sample"
            , 0xbc372967702082e1aa4fce892209f71ae4ad25a6dfd869334e6f153bd0c4d806
            , 0xdc9f4deada8d8ff588e98fed0ab690ffce858dc8c79376450eb6b76c24537e2c
            , 0xa65a9c3bc7babe286b195d5da68616da8d47fa0097f36dd19f517327dc848cec
            )
        ,
            ( H256
            , "sample"
            , 0x8926a27c40484216f052f4427cfd5647338b7b3939bc6573af4333569d597c52
            , 0xeace8bdbbe353c432a795d9ec556c6d021f7a03f42c36e9bc87e4ac7932cc809
            , 0x7081e175455f9247b812b74583e9e94f9ea79bd640dc962533b0680793a38d53
            )
        ,
            ( H384
            , "sample"
            , 0xc345d5ab3da0a5bcb7ec8f8fb7a7e96069e03b206371ef7d83e39068ec564920
            , 0xb2da945e91858834fd9bf616ebac151edbc4b45d27d0dd4a7f6a22739f45c00b
            , 0x19048b63d9fd6bca1d9bae3664e1bcb97f7276c306130969f63f38fa8319021b
            )
        ,
            ( H512
            , "sample"
            , 0x5a12994431785485b3f5f067221517791b85a597b7a9436995c89ed0374668fc
            , 0x2016ed092dc5fb669b8efb3d1f31a91eecb199879be0cf78f02ba062cb4c942e
            , 0xd0c76f84b5f091e141572a639a4fb8c230807eea7d55c8a154a224400aff2351
            )
        ,
            ( H1
            , "test"
            , 0x6eea486f9d41a037b2c640bc5645694ff8ff4b98d066a25f76be641ccb24ba4f
            , 0xc18270a93cfc6063f57a4dfa86024f700d980e4cf4e2cb65a504397273d98ea0
            , 0x414f22e5f31a8b6d33295c7539c1c1ba3a6160d7d68d50ac0d3a5beac2884faa
            )
        ,
            ( H224
            , "test"
            , 0x06bd4c05ed74719106223be33f2d95da6b3b541dad7bfbd7ac508213b6da6670
            , 0x272aba31572f6cc55e30bf616b7a265312018dd325be031be0cc82aa17870ea3
            , 0xe9cc286a52cce201586722d36d1e917eb96a4ebdb47932f9576ac645b3a60806
            )
        ,
            ( H256
            , "test"
            , 0x1d6ce6dda1c5d37307839cd03ab0a5cbb18e60d800937d67dfb4479aac8dead7
            , 0x8190012a1969f9957d56fccaad223186f423398d58ef5b3cefd5a4146a4476f0
            , 0x7452a53f7075d417b4b013b278d1bb8bbd21863f5e7b1cee679cf2188e1ab19e
            )
        ,
            ( H384
            , "test"
            , 0x206e61f73dbe1b2dc8be736b22b079e9dacd974db00eebbc5b64cad39cf9f91c
            , 0x239e66ddbe8f8c230a3d071d601b6ffbdfb5901f94d444c6af56f732beb954be
            , 0x6bd737513d5e72fe85d1c750e0f73921fe299b945aad1c802f15c26a43d34961
            )
        ,
            ( H512
            , "test"
            , 0xaff1651e4cd6036d57aa8b2a05ccf1a9d5a40166340ecbbdc55be10b568aa0aa
            , 0x89ec4bb1400eccff8e7d9aa515cd1de7803f2daff09693ee7fd1353e90a68307
            , 0xc9f0bdabcc0d880bb137a994cc7f3980ce91cc10faf529fc46565b15cea854e1
            )
        ]

-- | The nonce and the signature of RFC 6979, through 'DSA.deterministicNonce'
-- and 'DSA.signDeterministic', with the message's hash seeding the generator.
rfcCase :: DSA.PrivateKey -> (H, ByteString, Integer, Integer, Integer) -> Spec
rfcCase pk (h, m, k, r, s) = it (show h ++ " " ++ show m) $ case h of
    H1 -> check SHA1
    H224 -> check SHA224
    H256 -> check SHA256
    H384 -> check SHA384
    H512 -> check SHA512
  where
    check :: HashAlgorithm a => a -> Expectation
    check alg = do
        DSA.deterministicNonce alg pk (hashWith alg m) Just `shouldBe` k
        DSA.signDeterministic alg pk alg m `shouldBe` DSA.Signature r s

-- | What a hedged signer must do: give the same signature for the same
-- message and the same randomness, a different nonce -- so a different r --
-- for another message under that same randomness, a different signature for
-- other randomness, and signatures that verify.
hedged
    :: (Eq sig, Show sig, Eq r, Show r)
    => (ByteString -> (Word64, Word64, Word64, Word64, Word64) -> sig)
    -> (sig -> r)
    -> (ByteString -> sig -> Bool)
    -> Spec
hedged signAt rOf ok = do
    let s1 = signAt "message one" seedA
        s1' = signAt "message one" seedA
        s2 = signAt "message two" seedA
        s3 = signAt "message one" seedB
    it "repeats only for the same message and randomness" $ s1 `shouldBe` s1'
    it "changes the nonce with the message under repeated randomness" $
        rOf s1 `shouldNotBe` rOf s2
    it "changes with the randomness" $ s1 `shouldNotBe` s3
    it "verifies" $
        (ok "message one" s1, ok "message two" s2) `shouldBe` (True, True)
  where
    seedA = (1, 2, 3, 4, 5)
    seedB = (6, 7, 8, 9, 10)

spec :: Spec
spec = do
    describe "RFC 6979 deterministic DSA" $
        mapM_
            (\(Vector name pk cases) -> describe name $ mapM_ (rfcCase pk) cases)
            [dsa1024, dsa2048]
    describe "a generator hash whose digest is longer than its block" $
        it "still gives a nonce that signs" $ do
            let Vector _ pk _ = dsa2048
                pub = DSA.PublicKey (DSA.private_params pk) (dsaPublic pk)
                sig =
                    DSA.signDeterministic (SHAKE256 :: SHAKE256 2048) pk SHA256 ("m" :: ByteString)
            DSA.verify SHA256 pub sig ("m" :: ByteString) `shouldBe` True
    describe "hedged DSA" $ do
        let Vector _ pk _ = dsa2048
            pub = DSA.PublicKey (DSA.private_params pk) (dsaPublic pk)
        hedged
            (\m seed -> fst $ withDRG (drgNewTest seed) (DSA.sign pk SHA256 m))
            DSA.sign_r
            (\m sig -> DSA.verify SHA256 pub sig m)
    describe "hedged ECDSA" $ do
        let prx = Proxy :: Proxy ECC.Curve_P256R1
            d = throwCryptoError $ ECC.scalarFromInteger prx 0x1234567890abcdef
            q = ECDSA.toPublic prx d
        hedged
            (\m seed -> fst $ withDRG (drgNewTest seed) (ECDSA.sign prx d SHA256 m))
            (fst . ECDSA.signatureToIntegers prx)
            (\m sig -> ECDSA.verify prx SHA256 q sig m)
    describe "hedged ECDSA, Crypto.PubKey.ECC.ECDSA" $ do
        let curve = ECCT.getCurveByName ECCT.SEC_p384r1
            d = 0x1234567890abcdef
            priv = ECDSAOld.PrivateKey curve d
            pub = ECDSAOld.PublicKey curve (ECCG.generateQ curve d)
        hedged
            (\m seed -> fst $ withDRG (drgNewTest seed) (ECDSAOld.sign priv SHA256 m))
            ECDSAOld.sign_r
            (\m sig -> ECDSAOld.verify SHA256 pub sig m)
  where
    dsaPublic pk = DSA.calculatePublic (DSA.private_params pk) (DSA.private_x pk)
