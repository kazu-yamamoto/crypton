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
    binaryCurveMul,
) where

import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Number.Basic (numBytes)
import Crypto.Number.F2m (addF2m, divF2m, mulF2m, squareF2m)
import qualified Crypto.Number.Serialize.Internal as Internal
import Data.Bits (testBit)
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
        allocaBytes (sum widths) $ \base -> case scanl plusPtr base widths of
            (outx : outy : cx : cy : ca : cb : cp : ck : _) -> do
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
            _ -> return MulUnsupported -- there are eight, but say so anyway
  where
    !plen = numBytes p
    -- What the buffer holds, in this order: the two coordinates out, the two
    -- in, a, b, the prime, and the scalar.  The room to take and where each
    -- one starts both come from here, so they cannot drift apart.
    widths = [plen, plen, plen, plen, plen, plen, plen, klen]

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

-- | Multiply a point by a scalar on the curve @y^2 + x*y = x^3 + a*x^2 + b@
-- over the binary field of @fx@, by Montgomery's ladder.
--
-- The ladder carries the multiples of two consecutive numbers, whose
-- difference is therefore the point itself, and every bit of the scalar costs
-- one addition and one doubling of them whichever way it goes.  Only the x
-- coordinates are carried -- the difference being known is what lets them be
-- -- and the y is worked out at the end from the two of them, which is what
-- makes the coordinates projective: one division for the whole
-- multiplication rather than one for every step.
--
-- The point has to be on the curve and to have an x, which is what the
-- caller has to hand: the one point with no x is its own negation and is
-- easier multiplied the long way.  The scalar is walked over the whole of
-- the width asked for, so its value is hidden but that width is not.
binaryCurveMul
    :: Integer
    -- ^ the polynomial the field is over
    -> Integer
    -- ^ b
    -> Int
    -- ^ how many bits of scalar to walk
    -> Integer
    -- ^ the scalar
    -> Integer
    -- ^ the point's x
    -> Integer
    -- ^ the point's y
    -> MulResult
binaryCurveMul fx b bits k x y
    | bits <= 0 || k < 0 || x == 0 = MulUnsupported
    | otherwise = recover (go (bits - 1) (1, 0) (x, 1))
  where
    infixl 6 .+.
    (.+.) = addF2m
    sqr = squareF2m fx
    mul = mulF2m fx

    -- The two of them added, which the difference between them being the
    -- point makes possible from their x coordinates alone.  It does not
    -- matter which way round they come.
    madd (xa, za) (xb, zb) =
        let t1 = mul xa zb
            t2 = mul xb za
            z = sqr (t1 .+. t2)
         in (mul x z .+. mul t1 t2, z)

    -- One of them doubled.
    mdouble (xa, za) =
        let xa2 = sqr xa
            za2 = sqr za
         in (sqr xa2 .+. mul b (sqr za2), mul xa2 za2)

    -- Nothing is at infinity to begin with and the point is next to it, and
    -- from there each bit takes the pair to twice where it was.  The bangs
    -- are what make both halves happen: without them the one the bit does not
    -- call for would stay a thunk, and the work would follow the scalar.
    go i p1 p2
        | i < 0 = (p1, p2)
        | testBit k i =
            let !s = madd p1 p2
                !d = mdouble p2
             in go (i - 1) s d
        | otherwise =
            let !s = madd p1 p2
                !d = mdouble p1
             in go (i - 1) d s

    -- x1 is the answer and x2 is one point further on; together with the
    -- point they give the y that the ladder does not carry.
    recover ((x1, z1), (x2, z2))
        | z1 == 0 = MulInfinity -- the multiple is at infinity
        | z2 == 0 = MulPoint x (x .+. y) -- the one after it is, so this is -P
        | otherwise = case (divF2m fx x1 z1, divF2m fx x2 z2) of
            (Just xa, Just xb) ->
                let u = xa .+. x
                    v = xb .+. x
                    inner = mul u v .+. sqr x .+. y
                 in case divF2m fx (mul u inner) x of
                        Just w -> MulPoint xa (w .+. y)
                        Nothing -> MulUnsupported
            _ -> MulUnsupported
