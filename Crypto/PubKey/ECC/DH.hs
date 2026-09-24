-- |
-- Module      : Crypto.PubKey.ECC.DH
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Elliptic curve Diffie Hellman
module Crypto.PubKey.ECC.DH (
    Curve,
    PublicPoint,
    PrivateNumber,
    SharedKey (..),
    generatePrivate,
    calculatePublic,
    getShared,
    tryGetShared,
) where

import Crypto.Error (
    CryptoError (..),
    CryptoFailable (..),
    throwCryptoError,
 )
import Crypto.Number.Generate (generateMax)
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.PubKey.DH (SharedKey (..))
import Crypto.PubKey.ECC.Prim (isPointInSubgroup, isPointValid, pointMul)
import Crypto.PubKey.ECC.Types (
    Curve,
    Point (..),
    PrivateNumber,
    PublicPoint,
    common_curve,
    curveSizeBits,
    ecc_g,
    ecc_n,
 )
import Crypto.Random.Types

-- | Generating a private number d.
generatePrivate :: MonadRandom m => Curve -> m PrivateNumber
generatePrivate curve = generateMax n
  where
    n = ecc_n $ common_curve curve

-- | Generating a public point Q.
calculatePublic :: Curve -> PrivateNumber -> PublicPoint
calculatePublic curve d = q
  where
    g = ecc_g $ common_curve curve
    q = pointMul curve d g

-- | Generating a shared key using our private number and
--   the other party public point.
--
-- This raises the 'Crypto.Error.CryptoError' that 'tryGetShared' reports.  Use
-- 'tryGetShared' where the failure has to be handled.
getShared :: Curve -> PrivateNumber -> PublicPoint -> SharedKey
getShared curve db qa = throwCryptoError $ tryGetShared curve db qa

-- | Generating a shared key using our private number and the other party
--   public point, reporting a rejected point instead of raising.
--
-- The public point comes from the other party, so it is checked before it is
-- multiplied.  A point that does not satisfy the curve equation is reported as
-- 'CryptoError_PointCoordinatesInvalid'.
--
-- Satisfying the equation is not by itself membership of the subgroup the base
-- point generates; the two coincide only when the cofactor is 1.  On a curve
-- whose cofactor is above 1 the other party can offer a point of small order,
-- and the value that comes back then depends on our private number only
-- through its residue modulo that order, which hands them those bits.  So the
-- point is also required to be in the subgroup, by 'isPointInSubgroup', and is
-- reported as 'CryptoError_PointSubgroupInvalid' when it is not.  That check
-- costs one further scalar multiplication, and is skipped where the cofactor
-- is 1 and it cannot fail.
--
-- An exchange that yields the point at infinity, and so has no x coordinate to
-- derive the key from, is reported as 'CryptoError_ScalarMultiplicationInvalid'.
tryGetShared :: Curve -> PrivateNumber -> PublicPoint -> CryptoFailable SharedKey
tryGetShared curve db qa
    | not (isPointValid curve qa) = CryptoFailed CryptoError_PointCoordinatesInvalid
    | not (isPointInSubgroup curve qa) = CryptoFailed CryptoError_PointSubgroupInvalid
    | otherwise = case pointMul curve db qa of
        Point x _ -> CryptoPassed $ SharedKey $ i2ospOf_ ((nbBits + 7) `div` 8) x
        PointO -> CryptoFailed CryptoError_ScalarMultiplicationInvalid
  where
    nbBits = curveSizeBits curve
