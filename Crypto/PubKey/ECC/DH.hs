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
import Crypto.PubKey.ECC.Prim (pointMul)
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
getShared :: Curve -> PrivateNumber -> PublicPoint -> SharedKey
getShared curve db qa = SharedKey $ i2ospOf_ ((nbBits + 7) `div` 8) x
  where
    x = case pointMul curve db qa of
        Point x' _ -> x'
        _ -> error "getShared"
    nbBits = curveSizeBits curve
