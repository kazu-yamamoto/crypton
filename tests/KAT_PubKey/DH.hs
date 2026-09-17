{-# LANGUAGE OverloadedStrings #-}

module KAT_PubKey.DH (dhTests) where

import Control.Exception (ErrorCall, evaluate, try)
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.ECC.DH as ECDH
import Crypto.PubKey.ECC.Types

import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Data.Either (isLeft)

import Imports

-- | 'DH.SharedKey' wraps its bytes in a newtype, so evaluating it to weak head
-- normal form proves nothing.  Convert it to force the bytes themselves.
force :: DH.SharedKey -> IO (Either ErrorCall Int)
force sk = try (evaluate (B.length (convert sk :: ByteString)))

rejected :: String -> DH.SharedKey -> TestTree
rejected name sk = testCase name $ do
    result <- force sk
    assertBool "expected the exchange to be refused" (isLeft result)

p256 :: Curve
p256 = getCurveByName SEC_p256r1

-- | A peer point is attacker supplied, so it has to be checked to be on the
-- curve before it is multiplied by our private number: the curve equation is
-- what confines the result to the group the private number was chosen for.
-- Multiplying an off-curve point instead lands in whatever group that point
-- generates, and a small one leaks the private number.
ecdhTests :: TestTree
ecdhTests =
    testGroup
        "ECDH"
        [ testCase "a valid exchange agrees" $ do
            let qa = ECDH.calculatePublic p256 da
                qb = ECDH.calculatePublic p256 db
            ECDH.getShared p256 da qb @=? ECDH.getShared p256 db qa
        , rejected "a point not on the curve is refused" $
            ECDH.getShared p256 da (Point 1 1)
        , rejected "a point with a negative coordinate is refused" $
            ECDH.getShared p256 da (Point (-1) 1)
        , rejected "the point at infinity is refused" $
            ECDH.getShared p256 da PointO
        ]
  where
    da = 0x2eb7ef8e5dcbd0f0fbf70b5d4d43ea0b5f0dbcb45a3e3d8b3f1eaf7a35b1fb31
    db = 0x6c2f5e5b1e9a8d4c3b2a190807f6e5d4c3b2a1908f7e6d5c4b3a29180706f5e4d

dhTests :: TestTree
dhTests = testGroup "DH" [ecdhTests]
