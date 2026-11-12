{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
-- The binary curves are deprecated and still supported, so the tests
-- that hold them to their behaviour name them on purpose.
{-# OPTIONS_GHC -Wno-deprecations #-}

module ECDSASpec (spec) where

import qualified Crypto.ECC as ECDSA
import Crypto.Error
import Crypto.Hash
import qualified Crypto.PubKey.ECC.ECDSA as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECDSA as ECDSA
import qualified Data.ByteString as B
import Data.Maybe

import Imports

data Curve
    = forall curve.
        (ECDSA.EllipticCurveECDSA curve, Show (ECDSA.Scalar curve)) =>
      Curve curve ECC.Curve ECC.CurveName

instance Show Curve where
    showsPrec d (Curve _ _ name) = showsPrec d name

instance Arbitrary Curve where
    arbitrary =
        elements
            [ makeCurve ECDSA.Curve_P256R1 ECC.SEC_p256r1
            , makeCurve ECDSA.Curve_P384R1 ECC.SEC_p384r1
            , makeCurve ECDSA.Curve_P521R1 ECC.SEC_p521r1
            ]
      where
        makeCurve c name = Curve c (ECC.getCurveByName name) name

arbitraryScalar :: ECC.Curve -> Gen Integer
arbitraryScalar curve = choose (1, n - 1)
  where
    n = ECC.ecc_n (ECC.common_curve curve)

sigECDSAtoECC
    :: ECDSA.EllipticCurveECDSA curve
    => proxy curve -> ECDSA.Signature curve -> ECC.Signature
sigECDSAtoECC prx (ECDSA.Signature r s) = ECC.Signature (ECDSA.scalarToInteger prx r) (ECDSA.scalarToInteger prx s)

normalizeECC :: ECC.Curve -> ECC.Signature -> ECC.Signature
normalizeECC curve (ECC.Signature r s)
    | s <= n `div` 2 = ECC.Signature r s
    | otherwise = ECC.Signature r (n - s)
  where
    n = ECC.ecc_n $ ECC.common_curve curve

testRecover :: ECC.CurveName -> Spec
testRecover name = prop (show name) $ \(ArbitraryBS0_2901 msg) -> do
    let curve = ECC.getCurveByName name
    let n = ECC.ecc_n $ ECC.common_curve curve
    k <- choose (1, n - 1)
    d <- choose (1, n - 1)
    let key = ECC.PrivateKey curve d
    let digest = hashWith SHA256 msg
    let pub =
            ECC.signExtendedDigestWith k key digest >>= \signature -> ECC.recoverDigest curve signature digest
    pure $
        propertyHold
            [eqTest "recovery" (Just $ ECC.generateQ curve d) (ECC.public_q <$> pub)]

testNormalize :: ECC.CurveName -> Spec
testNormalize name = prop (show name) $ \(ArbitraryBS0_2901 msg) -> do
    let curve = ECC.getCurveByName name
    let n = ECC.ecc_n $ ECC.common_curve curve
    k <- choose (1, n - 1)
    d <- choose (1, n - 1)
    let key = ECC.PrivateKey curve d
    let digest = hashWith SHA256 msg
    let check =
            ECC.signExtendedDigestWith k key digest >>= \s -> pure $ ECC.sign_s (ECC.signature s) <= n `div` 2
    pure $ propertyHold [eqTest "normalized" (Just True) check]

-- | The deterministic nonce of RFC 6979, against the implementation in
-- Crypto.PubKey.ECC.ECDSA, which is itself held to the vectors in the RFC by
-- tests/PubKey/ECDSASpec.hs.  Agreeing with it is agreeing with those.
propertyDeterministic
    :: HashAlgorithm hash => hash -> Curve -> ArbitraryBS0_2901 -> Gen Bool
propertyDeterministic hashAlg (Curve c curve _) (ArbitraryBS0_2901 msg) = do
    d <- arbitraryScalar curve
    let prx = Just c -- using Maybe as Proxy
        privECC = ECC.PrivateKey curve d
        privECDSA = throwCryptoError $ ECDSA.scalarFromInteger prx d
        pubECDSA = ECDSA.toPublic prx privECDSA
        digest = hashWith hashAlg msg
        kECC = ECC.deterministicNonce hashAlg privECC digest Just
        kECDSA =
            ECDSA.deterministicNonce prx hashAlg privECDSA digest Just
        sigECDSA = ECDSA.signDeterministic prx hashAlg privECDSA hashAlg msg
        sigWithK = fromJust $ ECDSA.signWith prx kECDSA privECDSA hashAlg msg
    pure $
        propertyHold
            [ eqTest "nonce" kECC (ECDSA.scalarToInteger prx kECDSA)
            , eqTest "signature matches signWith" sigWithK sigECDSA
            , eqTest
                "signature verifies"
                True
                (ECDSA.verify prx hashAlg pubECDSA sigECDSA msg)
            ]

spec :: Spec
spec = do
    modifyMaxSuccess (const 5) $
        describe "RFC 6979 deterministic nonce" $ do
            prop "SHA1" $ propertyDeterministic SHA1
            prop "SHA224" $ propertyDeterministic SHA224
            prop "SHA256" $ propertyDeterministic SHA256
            prop "SHA384" $ propertyDeterministic SHA384
            prop "SHA512" $ propertyDeterministic SHA512
    modifyMaxSuccess (const 5) $
        describe "verification" $ do
            prop "SHA1" $ propertyECDSA SHA1
            prop "SHA224" $ propertyECDSA SHA224
            prop "SHA256" $ propertyECDSA SHA256
            prop "SHA384" $ propertyECDSA SHA384
            prop "SHA512" $ propertyECDSA SHA512
    -- a zero k used to raise "cannot create point from zero" on P-256,
    -- where P-384 and P-521 gave Nothing
    describe "zero scalar" $ do
        it "signWith k = 0 gives Nothing on every NIST curve" $ do
            zeroK ECDSA.Curve_P256R1 `shouldBe` True
            zeroK ECDSA.Curve_P384R1 `shouldBe` True
            zeroK ECDSA.Curve_P521R1 `shouldBe` True
        it "pointBaseSmul 0 is the point at infinity on P-256" $
            ECDSA.pointBaseSmul (Just ECDSA.Curve_P256R1) zero256
                `shouldBe` ECDSA.pointAdd
                    (Just ECDSA.Curve_P256R1)
                    g256
                    (ECDSA.pointNegate (Just ECDSA.Curve_P256R1) g256)
    describe "recovery" $ do
        -- SEC 1 4.1.6 refuses these; they used to recover some key
        it "refuses s = 0, and an x at or past p" $ do
            let k1 = ECC.getCurveByName ECC.SEC_p256k1
                cc = ECC.common_curve k1
                n = ECC.ecc_n cc
                p = case k1 of
                    ECC.CurveFP (ECC.CurvePrime q _) -> q
                    _ -> error "secp256k1 is a prime curve"
                digest = hashWith SHA256 (B.pack [1, 2, 3])
                rec i r s =
                    ECC.recoverDigest k1 (ECC.ExtendedSignature i False (ECC.Signature r s)) digest
            rec 0 1 0 `shouldBe` Nothing
            rec 0 n 1 `shouldBe` Nothing
            rec 1 (p - n) 1 `shouldBe` Nothing
        modifyMaxSuccess (const 100) $ testRecover ECC.SEC_p128r1
        modifyMaxSuccess (const 100) $ testRecover ECC.SEC_p128r2
        modifyMaxSuccess (const 100) $ testRecover ECC.SEC_p256k1
        modifyMaxSuccess (const 100) $ testRecover ECC.SEC_p256r1
        modifyMaxSuccess (const 50) $ testRecover ECC.SEC_t131r1
        modifyMaxSuccess (const 50) $ testRecover ECC.SEC_t131r2
        modifyMaxSuccess (const 20) $ testRecover ECC.SEC_t233k1
        modifyMaxSuccess (const 20) $ testRecover ECC.SEC_t233r1
    describe "normalize" $ do
        modifyMaxSuccess (const 100) $ testNormalize ECC.SEC_p128r1
        modifyMaxSuccess (const 100) $ testNormalize ECC.SEC_p128r2
        modifyMaxSuccess (const 100) $ testNormalize ECC.SEC_p256k1
        modifyMaxSuccess (const 100) $ testNormalize ECC.SEC_p256r1
        modifyMaxSuccess (const 50) $ testNormalize ECC.SEC_t131r1
        modifyMaxSuccess (const 50) $ testNormalize ECC.SEC_t131r2
        modifyMaxSuccess (const 20) $ testNormalize ECC.SEC_t233k1
        modifyMaxSuccess (const 20) $ testNormalize ECC.SEC_t233r1
  where
    propertyECDSA hashAlg (Curve c curve _) (ArbitraryBS0_2901 msg) = do
        d <- arbitraryScalar curve
        kECC <- arbitraryScalar curve
        let privECC = ECC.PrivateKey curve d
            prx = Just c -- using Maybe as Proxy
            kECDSA = throwCryptoError $ ECDSA.scalarFromInteger prx kECC
            privECDSA = throwCryptoError $ ECDSA.scalarFromInteger prx d
            pubECDSA = ECDSA.toPublic prx privECDSA
            sigECC = fromJust $ ECC.signWith kECC privECC hashAlg msg
            sigECDSA = fromJust $ ECDSA.signWith prx kECDSA privECDSA hashAlg msg
            msg' = msg `B.append` B.singleton 42
        return $
            propertyHold
                [ eqTest "signature" sigECC $ normalizeECC curve $ sigECDSAtoECC prx sigECDSA
                , eqTest "verification" True (ECDSA.verify prx hashAlg pubECDSA sigECDSA msg)
                , eqTest "alteration" False (ECDSA.verify prx hashAlg pubECDSA sigECDSA msg')
                ]

zeroK
    :: (ECDSA.EllipticCurveECDSA curve, ECDSA.EllipticCurveBasepointArith curve)
    => curve -> Bool
zeroK curve = isNothing (ECDSA.signWith prx k d SHA256 (B.pack [1, 2, 3]))
  where
    prx = Just curve
    k = throwCryptoError (ECDSA.scalarFromInteger prx 0)
    d = throwCryptoError (ECDSA.scalarFromInteger prx 12345)

zero256 :: ECDSA.Scalar ECDSA.Curve_P256R1
zero256 = throwCryptoError (ECDSA.scalarFromInteger (Just ECDSA.Curve_P256R1) 0)

g256 :: ECDSA.Point ECDSA.Curve_P256R1
g256 =
    ECDSA.pointBaseSmul
        (Just ECDSA.Curve_P256R1)
        (throwCryptoError (ECDSA.scalarFromInteger (Just ECDSA.Curve_P256R1) 1))
