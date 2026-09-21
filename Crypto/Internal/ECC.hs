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
    primeCurveTableMul,
    baseTable,
    binaryCurveMul,
    binaryCurveC,
) where

import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Number.Basic (numBits, numBytes)
import Crypto.Number.F2m (addF2m, divF2m, mulF2m, squareF2m)
import qualified Crypto.Number.Serialize.Internal as Internal
import Crypto.PubKey.ECC.Types (
    Curve (..),
    CurveCommon (..),
    CurveName,
    CurvePrime (..),
    Point (..),
    getCurveByName,
 )
import Data.Bits (testBit)
import Data.Word (Word32, Word8)
import Foreign.C.Types (CInt (..))
import Foreign.ForeignPtr (ForeignPtr, mallocForeignPtrBytes, withForeignPtr)
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

foreign import ccall unsafe "crypton_ecc_table_size"
    c_ecc_table_size :: Word32 -> Word32 -> Word32

foreign import ccall safe "crypton_ecc_table_build"
    c_ecc_table_build
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> IO CInt

foreign import ccall safe "crypton_ecc_table_mul"
    c_ecc_table_mul
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> IO CInt

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

-- | The table for the base point of a curve the library knows, which is the
-- point signing and making a key multiply and the only point worth keeping a
-- table for.  The curves are told apart by their numbers, which are public,
-- so both of the elliptic curve APIs find the same table.
--
-- Each is built when it is first wanted and kept for as long as the program
-- runs, and a curve nobody multiplies the base point of never has one built.
-- Building costs 2.8 ms for secp256k1, 5.5 for secp384r1 and 10.6 for
-- secp521r1, and the last two take 221 KB and 456 KB.  A multiplication with
-- the table takes about a third of what one without it takes, so the build
-- pays for itself after about fifteen of them: a program that signs many
-- times wins, and one that signs once and exits does not.
baseTable
    :: Integer
    -- ^ p
    -> Integer
    -- ^ a
    -> Integer
    -- ^ b
    -> Int
    -- ^ how many bytes of scalar are wanted
    -> Integer
    -- ^ the base point's x
    -> Integer
    -- ^ the base point's y
    -> Maybe (ForeignPtr Word8)
baseTable p a b klen gx gy =
    case lookup (p, a, b, klen, gx, gy) baseTables of
        Just table -> table
        Nothing -> Nothing

type TableKey = (Integer, Integer, Integer, Int, Integer, Integer)

baseTables :: [(TableKey, Maybe (ForeignPtr Word8))]
baseTables =
    [ ((p, a, b, klen, gx, gy), primeCurveTable p a b klen gx gy)
    | name <- [minBound .. maxBound] :: [CurveName]
    , CurveFP (CurvePrime p cc) <- [getCurveByName name]
    , Point gx gy <- [ecc_g cc]
    , let a = ecc_a cc
    , let b = ecc_b cc
    , let klen = numBytes (ecc_n cc)
    ]
{-# NOINLINE baseTables #-}

-- | The multiples of a point that 'primeCurveTableMul' wants: for every four
-- bits of a scalar, the sixteen points those bits can call for.  Building it
-- costs a few thousand point operations, and what it saves is all the
-- doublings of every multiplication that uses it, so it is worth keeping for
-- as long as the point is -- which for a curve's base point is forever.
--
-- The arguments are as for 'primeCurveMul'.  'Nothing' means the C would not
-- take them.
primeCurveTable
    :: Integer
    -- ^ p
    -> Integer
    -- ^ a
    -> Integer
    -- ^ b
    -> Int
    -- ^ how many bytes of scalar the table is to cover
    -> Integer
    -- ^ the point's x
    -> Integer
    -- ^ the point's y
    -> Maybe (ForeignPtr Word8)
primeCurveTable p a b klen px py
    | p <= 0 || even p || klen <= 0 || size == 0 = Nothing
    | otherwise = unsafeDoIO $ do
        table <- mallocForeignPtrBytes (fromIntegral size)
        allocaBytes (5 * plen) $ \cx -> do
            let cy = cx `plusPtr` plen
                ca = cy `plusPtr` plen
                cb = ca `plusPtr` plen
                cp = cb `plusPtr` plen
            _ <- Internal.i2ospOf px cx plen
            _ <- Internal.i2ospOf py cy plen
            _ <- Internal.i2ospOf a ca plen
            _ <- Internal.i2ospOf b cb plen
            _ <- Internal.i2ospOf p cp plen
            r <- withForeignPtr table $ \t ->
                c_ecc_table_build
                    t
                    cx
                    cy
                    (fromIntegral klen)
                    ca
                    cb
                    cp
                    (fromIntegral plen)
            return $ if r == 0 then Just table else Nothing
  where
    !plen = numBytes p
    !size = c_ecc_table_size (fromIntegral plen) (fromIntegral klen)

-- | Multiply the point a table was built for by a scalar of the width the
-- table was built for.  One addition for every four bits and no doublings.
primeCurveTableMul
    :: ForeignPtr Word8
    -- ^ the table
    -> Integer
    -- ^ p
    -> Integer
    -- ^ a
    -> Integer
    -- ^ b
    -> Int
    -- ^ the width the table was built for
    -> Integer
    -- ^ the scalar
    -> MulResult
primeCurveTableMul table p a b klen k
    | p <= 0 || even p || klen <= 0 || k < 0 = MulUnsupported
    | otherwise = unsafeDoIO $
        allocaBytes (sum widths) $ \base -> case scanl plusPtr base widths of
            (outx : outy : ca : cb : cp : ck : _) -> do
                _ <- Internal.i2ospOf a ca plen
                _ <- Internal.i2ospOf b cb plen
                _ <- Internal.i2ospOf p cp plen
                _ <- Internal.i2ospOf k ck klen
                r <- withForeignPtr table $ \t ->
                    c_ecc_table_mul
                        outx
                        outy
                        t
                        ck
                        (fromIntegral klen)
                        ca
                        cb
                        cp
                        (fromIntegral plen)
                Internal.i2ospOf 0 ck klen >> return ()
                case r of
                    0 -> do
                        !x <- Internal.os2ip outx plen
                        !y <- Internal.os2ip outy plen
                        return (MulPoint x y)
                    1 -> return MulInfinity
                    _ -> return MulUnsupported
            _ -> return MulUnsupported -- there are six, but say so anyway
  where
    !plen = numBytes p
    widths = [plen, plen, plen, plen, plen, klen]

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

-- | Multiply a point by a scalar on a curve over a binary field, in C.
--
-- The ladder is the same one 'binaryCurveMul' walks, but the field arithmetic
-- is carry-less multiplication -- the processor's where it has it, and four
-- interleaved groups of bits where it does not -- rather than 'Integer'
-- shifts and exclusive ors, and nothing in it branches on the scalar or
-- indexes memory with it.
--
-- The point has to be on the curve and to have an x, and the scalar is walked
-- over the whole of the width asked for, as for 'primeCurveMul'.
binaryCurveC
    :: Integer
    -- ^ the polynomial the field is over
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
binaryCurveC fx b klen k px py
    | fx <= 1 || klen <= 0 || k < 0 || px <= 0 || flen <= 0 = MulUnsupported
    | otherwise = unsafeDoIO $
        allocaBytes (sum widths) $ \base -> case scanl plusPtr base widths of
            (outx : outy : cx : cy : cb : cf : ck : _) -> do
                _ <- Internal.i2ospOf px cx flen
                _ <- Internal.i2ospOf py cy flen
                _ <- Internal.i2ospOf b cb flen
                _ <- Internal.i2ospOf fx cf fxlen
                _ <- Internal.i2ospOf k ck klen
                r <-
                    c_f2m_mul
                        outx
                        outy
                        cx
                        cy
                        ck
                        (fromIntegral klen)
                        cb
                        (fromIntegral flen)
                        cf
                        (fromIntegral fxlen)
                Internal.i2ospOf 0 ck klen >> return ()
                case r of
                    0 -> do
                        !x <- Internal.os2ip outx flen
                        !y <- Internal.os2ip outy flen
                        return (MulPoint x y)
                    1 -> return MulInfinity
                    _ -> return MulUnsupported
            _ -> return MulUnsupported -- there are seven, but say so anyway
  where
    -- the field is the degree of the polynomial, which is one under its width
    !flen = (numBits fx - 1 + 7) `div` 8
    !fxlen = numBytes fx
    widths = [flen, flen, flen, flen, flen, fxlen, klen]

foreign import ccall safe "crypton_f2m_mul"
    c_f2m_mul
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Word32
        -> IO CInt
