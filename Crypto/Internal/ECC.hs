{-# LANGUAGE BangPatterns #-}

-- |
-- Module      : Crypto.Internal.ECC
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : Good
--
-- The C scalar multiplication for curves over a prime field, which both of
-- the elliptic curve APIs reach for.
module Crypto.Internal.ECC (
    MulResult (..),
    primeCurveMul,
) where

import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Number.Basic (numBytes)
import qualified Crypto.Number.Serialize.Internal as Internal
import Data.Word (Word32, Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, plusPtr)

-- | What the C made of it.
data MulResult
    = -- | the point it arrived at
      MulPoint !Integer !Integer
    | -- | the point at infinity, which has no coordinates
      MulInfinity
    | -- | not something the C works with, so the caller has to
      MulUnsupported
    deriving (Show, Eq)

-- | Multiply a point by a scalar on the curve @y^2 = x^3 + a*x + b@ over the
-- field of @p@, which has to be an odd prime.  The point has to be on the
-- curve and not the point at infinity, and its coordinates, @a@ and @b@ have
-- to be under @p@; the caller has all of that to hand and the C does not
-- check it.
--
-- The scalar is walked four bits at a time over the whole of the width asked
-- for, so its value is hidden but that width is not.  Ask for the width of
-- the curve's order, which is public, and every scalar in range costs the
-- same.
primeCurveMul
    :: Integer
    -- ^ p
    -> Integer
    -- ^ a
    -> Integer
    -- ^ b
    -> Int
    -- ^ how many bytes of scalar to walk
    -> Integer
    -- ^ the scalar
    -> Integer
    -- ^ the point's x
    -> Integer
    -- ^ the point's y
    -> MulResult
primeCurveMul p a b klen k px py
    | p <= 0 || even p || klen <= 0 || k < 0 = MulUnsupported
    | otherwise = unsafeDoIO $
        allocaBytes (6 * plen + klen) $ \outx -> do
            let outy = outx `plusPtr` plen
                cx = outy `plusPtr` plen
                cy = cx `plusPtr` plen
                ca = cy `plusPtr` plen
                cb = ca `plusPtr` plen
                cp = cb `plusPtr` plen
                ck = cp `plusPtr` plen
            _ <- Internal.i2ospOf px cx plen
            _ <- Internal.i2ospOf py cy plen
            _ <- Internal.i2ospOf a ca plen
            _ <- Internal.i2ospOf b cb plen
            _ <- Internal.i2ospOf p cp plen
            _ <- Internal.i2ospOf k ck klen
            r <-
                c_ecc_mul
                    outx
                    outy
                    cx
                    cy
                    ck
                    (fromIntegral klen)
                    ca
                    cb
                    cp
                    (fromIntegral plen)
            -- the scalar is the caller's secret, and this is the last place
            -- it is written out in the clear
            Internal.i2ospOf 0 ck klen >> return ()
            case r of
                0 -> do
                    !x <- Internal.os2ip outx plen
                    !y <- Internal.os2ip outy plen
                    return (MulPoint x y)
                1 -> return MulInfinity
                _ -> return MulUnsupported
  where
    !plen = numBytes p

foreign import ccall safe "crypton_ecc_mul"
    c_ecc_mul
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> IO CInt
