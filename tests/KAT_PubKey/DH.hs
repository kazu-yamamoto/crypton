{-# LANGUAGE OverloadedStrings #-}

module KAT_PubKey.DH (dhTests) where

import Control.Exception (SomeException, evaluate, try)
import Crypto.Error
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.ECC.DH as ECDH
import Crypto.PubKey.ECC.Types

import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Data.Either (isLeft)

import Imports

-- | 'DH.SharedKey' wraps its bytes in a newtype, so evaluating it to weak head
-- normal form proves nothing.  Convert it to force the bytes themselves.
force :: DH.SharedKey -> IO (Either String Int)
force sk = do
    result <- try (evaluate (B.length (convert sk :: ByteString)))
    return $ either (Left . takeWhile (/= '\n') . showExc) Right result
  where
    showExc :: SomeException -> String
    showExc = show

rejected :: String -> DH.SharedKey -> Spec
rejected name sk = it name $ do
    result <- force sk
    assertBool "expected the exchange to be refused" (isLeft result)

p256 :: Curve
p256 = getCurveByName SEC_p256r1

-- | A peer point is attacker supplied, so it has to be checked to be on the
-- curve before it is multiplied by our private number: the curve equation is
-- what confines the result to the group the private number was chosen for.
-- Multiplying an off-curve point instead lands in whatever group that point
-- generates, and a small one leaks the private number.
ecdhTests :: Spec
ecdhTests =
    describe "ECDH" $ do
        it "a valid exchange agrees" $ do
            let qa = ECDH.calculatePublic p256 da
                qb = ECDH.calculatePublic p256 db
            ECDH.getShared p256 db qa `shouldBe` ECDH.getShared p256 da qb
        rejected "a point not on the curve is refused" $
            ECDH.getShared p256 da (Point 1 1)
        rejected "a point with a negative coordinate is refused" $
            ECDH.getShared p256 da (Point (-1) 1)
        rejected "the point at infinity is refused" $
            ECDH.getShared p256 da PointO
        it "getShared' agrees with getShared on a valid exchange" $ do
            let qb = ECDH.calculatePublic p256 db
            ECDH.getShared' p256 da qb `shouldBe` CryptoPassed (ECDH.getShared p256 da qb)
        it "getShared' reports a point not on the curve" $
            ECDH.getShared' p256 da (Point 1 1)
                `shouldBe` CryptoFailed CryptoError_PointCoordinatesInvalid
        it "getShared' reports a negative coordinate" $
            ECDH.getShared' p256 da (Point (-1) 1)
                `shouldBe` CryptoFailed CryptoError_PointCoordinatesInvalid
        it "getShared' reports the point at infinity" $
            ECDH.getShared' p256 da PointO
                `shouldBe` CryptoFailed CryptoError_ScalarMultiplicationInvalid
  where
    da = 0x2eb7ef8e5dcbd0f0fbf70b5d4d43ea0b5f0dbcb45a3e3d8b3f1eaf7a35b1fb31
    db = 0x6c2f5e5b1e9a8d4c3b2a190807f6e5d4c3b2a1908f7e6d5c4b3a29180706f5e4d

-- | RFC 7919 section 5.1 requires the peer's public value y to satisfy
-- 1 < y < p-1.  The excluded values generate the subgroup {1} or {1, p-1}, so
-- the shared secret they produce is one of a handful of constants and carries
-- none of our private number's secrecy.
--
-- 'Params' also carries the size of p separately from p itself, and only p and
-- g travel on the wire, so the two can disagree; the shared secret must still
-- be the size p calls for rather than raising from i2ospOf_.
ffdhTests :: Spec
ffdhTests =
    describe "finite field" $ do
        it "a valid exchange agrees" $ do
            let ya = DH.calculatePublic params xa
                yb = DH.calculatePublic params xb
            DH.getShared params xb ya `shouldBe` DH.getShared params xa yb
        rejected "y = 0 is refused" $ DH.getShared params xa 0
        rejected "y = 1 is refused" $ DH.getShared params xa 1
        rejected "y = p-1 is refused" $
            DH.getShared params xa (DH.PublicNumber (p - 1))
        rejected "y = p is refused" $ DH.getShared params xa (DH.PublicNumber p)
        rejected "y > p is refused" $ DH.getShared params xa (DH.PublicNumber (p + 1))
        it "getShared' agrees with getShared on a valid exchange" $ do
            let yb = DH.calculatePublic params xb
            DH.getShared' params xa yb `shouldBe` CryptoPassed (DH.getShared params xa yb)
        it "getShared' reports a public number out of range" $
            mapM_
                ( \y ->
                    DH.getShared' params xa (DH.PublicNumber y)
                        `shouldBe` CryptoFailed CryptoError_ParameterInvalid
                )
                [0, 1, p - 1, p, p + 1]
        it "an understated bit size still yields p-sized output" $ do
            let understated = DH.Params p 2 8
                yb = DH.calculatePublic understated xb
            result <- force (DH.getShared understated xa yb)
            result `shouldBe` Right 128
  where
    -- RFC 7919 ffdhe1024 is not defined, so use the 1024-bit MODP group of
    -- RFC 2409 section 6.2, whose generator is 2
    p =
        0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
    params = DH.Params p 2 1024
    xa = DH.PrivateNumber 0x1f3b5d79a2c4e60813579bdf2468ace0
    xb = DH.PrivateNumber 0x2c4e60813579bdf2468ace01f3b5d79a

dhTests :: Spec
dhTests = describe "DH" $ do
    ecdhTests
    ffdhTests
