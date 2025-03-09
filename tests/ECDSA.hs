{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}

module ECDSA (tests) where

import Data.Maybe
import qualified Crypto.ECC as ECDSA
import Crypto.Error
import Crypto.Hash
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECDSA as ECDSA
import qualified Data.ByteString as B

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

sigECDSAtoECC :: ECDSA.EllipticCurveECDSA curve => proxy curve -> ECDSA.Signature curve -> ECC.Signature
sigECDSAtoECC prx (ECDSA.Signature r s) = ECC.Signature (ECDSA.scalarToInteger prx r) (ECDSA.scalarToInteger prx s)

normalizeECC :: ECC.Curve -> ECC.Signature -> ECC.Signature
normalizeECC curve (ECC.Signature r s)
    | s <= n `div` 2 = ECC.Signature r s
    | otherwise = ECC.Signature r (n - s)
    where n = ECC.ecc_n $ ECC.common_curve curve

testRecover :: ECC.CurveName -> TestTree
testRecover name = testProperty (show name) $ \ (ArbitraryBS0_2901 msg) -> do
    let curve = ECC.getCurveByName name
    let n = ECC.ecc_n $ ECC.common_curve curve
    k <- choose (1, n - 1)
    d <- choose (1, n - 1)
    let key = ECC.PrivateKey curve d
    let digest = hashWith SHA256 msg
    let pub = ECC.signExtendedDigestWith k key digest >>= \ signature -> ECC.recoverDigest curve signature digest
    pure $ propertyHold [eqTest "recovery" (Just $ ECC.generateQ curve d) (ECC.public_q <$> pub)]

testNormalize :: ECC.CurveName -> TestTree
testNormalize name = testProperty (show name) $ \ (ArbitraryBS0_2901 msg) -> do
    let curve = ECC.getCurveByName name
    let n = ECC.ecc_n $ ECC.common_curve curve
    k <- choose (1, n - 1)
    d <- choose (1, n - 1)
    let key = ECC.PrivateKey curve d
    let digest = hashWith SHA256 msg
    let check = ECC.signExtendedDigestWith k key digest >>= \ s -> pure $ ECC.sign_s (ECC.signature s) <= n `div` 2
    pure $ propertyHold [eqTest "normalized" (Just True) check]

tests :: TestTree
tests = testGroup "ECDSA"
    [ localOption (QuickCheckTests 5) $
        testGroup
            "verification"
            [ testProperty "SHA1" $ propertyECDSA SHA1
            , testProperty "SHA224" $ propertyECDSA SHA224
            , testProperty "SHA256" $ propertyECDSA SHA256
            , testProperty "SHA384" $ propertyECDSA SHA384
            , testProperty "SHA512" $ propertyECDSA SHA512
            ]
    , testGroup "recovery"
        [ localOption (QuickCheckTests 100) $ testRecover ECC.SEC_p128r1
        , localOption (QuickCheckTests 100) $ testRecover ECC.SEC_p128r2
        , localOption (QuickCheckTests 100) $ testRecover ECC.SEC_p256k1
        , localOption (QuickCheckTests 100) $ testRecover ECC.SEC_p256r1
        , localOption (QuickCheckTests 50) $ testRecover ECC.SEC_t131r1
        , localOption (QuickCheckTests 50) $ testRecover ECC.SEC_t131r2
        , localOption (QuickCheckTests 20) $ testRecover ECC.SEC_t233k1
        , localOption (QuickCheckTests 20) $ testRecover ECC.SEC_t233r1
        ]
    , testGroup "normalize"
        [ localOption (QuickCheckTests 100) $ testNormalize ECC.SEC_p128r1
        , localOption (QuickCheckTests 100) $ testNormalize ECC.SEC_p128r2
        , localOption (QuickCheckTests 100) $ testNormalize ECC.SEC_p256k1
        , localOption (QuickCheckTests 100) $ testNormalize ECC.SEC_p256r1
        , localOption (QuickCheckTests 50) $ testNormalize ECC.SEC_t131r1
        , localOption (QuickCheckTests 50) $ testNormalize ECC.SEC_t131r2
        , localOption (QuickCheckTests 20) $ testNormalize ECC.SEC_t233k1
        , localOption (QuickCheckTests 20) $ testNormalize ECC.SEC_t233r1
        ]
    ]
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
