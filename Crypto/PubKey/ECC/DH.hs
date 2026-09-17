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
) where

import Crypto.Number.Generate (generateMax)
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.PubKey.DH (SharedKey (..))
import Crypto.PubKey.ECC.Prim (isPointValid, pointMul)
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
-- The public point comes from the other party, so it is checked to be on the
-- curve first: the curve equation is what confines the result to the group our
-- private number was chosen for, and multiplying a point that does not satisfy
-- it lands in whatever group that point generates instead, which may be small
-- enough to recover the private number from.  A point that fails the check, or
-- one that multiplies to the point at infinity and so yields no x coordinate,
-- raises an 'error'.
--
-- 'Crypto.ECC.ecdh' reports the same conditions as a 'Crypto.Error.CryptoFailed'
-- instead, and should be preferred where a failure has to be handled.
getShared :: Curve -> PrivateNumber -> PublicPoint -> SharedKey
getShared curve db qa
    | not (isPointValid curve qa) =
        error "Crypto.PubKey.ECC.DH.getShared: peer point is not on the curve"
    | otherwise = SharedKey $ i2ospOf_ ((nbBits + 7) `div` 8) x
  where
    x = case pointMul curve db qa of
        Point x' _ -> x'
        _ ->
            error
                "Crypto.PubKey.ECC.DH.getShared: the exchange yielded the point at infinity"
    nbBits = curveSizeBits curve
