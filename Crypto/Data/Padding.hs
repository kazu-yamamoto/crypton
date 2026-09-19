-- |
-- Module      : Crypto.Data.Padding
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Various cryptographic padding commonly used for block ciphers
-- or asymmetric systems.
module Crypto.Data.Padding (
    Format (..),
    pad,
    unpad,
) where

import Data.ByteArray (ByteArray, Bytes)
import qualified Data.ByteArray as B

-- | Format of padding
data Format
    = -- | PKCS5: PKCS7 with hardcoded size of 8
      PKCS5
    | -- | PKCS7 with padding size between 1 and 255
      PKCS7 Int
    | -- | Zero padding with block size, which must be at least 1.
      --
      -- Zero padding does not say how much of it there is, so 'unpad' cannot
      -- undo 'pad': see 'unpad'.
      ZERO Int
    deriving (Show, Eq)

-- | Is this a block size PKCS7 can describe?
--
-- The padding octet carries the number of octets added, so it cannot describe
-- a block longer than 255, and a block of zero has nothing to describe.
-- Outside that range the octet would be computed as an 'Int' and then narrowed
-- to a 'Data.Word.Word8', which wraps: 'pad' and 'unpad' would agree on the
-- wrapped value and hand back something other than what was padded.
pkcs7SizeValid :: Int -> Bool
pkcs7SizeValid sz = sz >= 1 && sz <= 255

-- | Is this a block size 'ZERO' can use?
--
-- Nothing is written into the padding, so there is no upper bound to match
-- the one 'PKCS7' has; but a block of zero or fewer octets is not a block,
-- and the length is taken modulo it.
zeroSizeValid :: Int -> Bool
zeroSizeValid sz = sz >= 1

-- | Apply some pad to a bytearray
--
-- A 'PKCS7' block size outside 1..255, or a 'ZERO' block size below 1, raises
-- an 'error'; 'unpad' reports the same condition as 'Nothing'.
pad :: ByteArray byteArray => Format -> byteArray -> byteArray
pad PKCS5 bin = pad (PKCS7 8) bin
pad (PKCS7 sz) bin
    | not (pkcs7SizeValid sz) =
        error $
            "Crypto.Data.Padding: PKCS7 block size "
                ++ show sz
                ++ " is not between 1 and 255"
    | otherwise = bin `B.append` paddingString
  where
    paddingString = B.replicate paddingByte (fromIntegral paddingByte)
    paddingByte = sz - (B.length bin `mod` sz)
pad (ZERO sz) bin
    | not (zeroSizeValid sz) =
        error $
            "Crypto.Data.Padding: ZERO block size "
                ++ show sz
                ++ " is not at least 1"
    | otherwise = bin `B.append` paddingString
  where
    paddingString = B.replicate paddingSz 0
    paddingSz
        | len == 0 = sz
        | m == 0 = 0
        | otherwise = sz - m
    m = len `mod` sz
    len = B.length bin

-- | Try to remove some padding from a bytearray.
--
-- 'PKCS7' padding says how long it is, so this undoes 'pad' exactly.
--
-- 'ZERO' padding says nothing, and 'pad' adds none at all when the input is
-- already a multiple of the block size, so there is no way to tell padding
-- from data that happens to end in zero octets.  This therefore does not undo
-- 'pad': it returns the input unchanged when the last octet is not zero, and
-- 'Nothing' when it is, rather than guess and hand back less than it was
-- given.  Zero padding is only usable where the original length is known by
-- other means.
unpad PKCS5 bin = unpad (PKCS7 8) bin
unpad (PKCS7 sz) bin
    | not (pkcs7SizeValid sz) = Nothing
    | len == 0 = Nothing
    | (len `mod` sz) /= 0 = Nothing
    -- the padded length is a multiple of the block size and the padding is
    -- what was added to reach it, so it is never more than one block
    | paddingSz < 1 || paddingSz > sz = Nothing
    | paddingWitness `B.constEq` padding = Just content
    | otherwise = Nothing
  where
    len = B.length bin
    paddingByte = B.index bin (len - 1)
    paddingSz = fromIntegral paddingByte
    (content, padding) = B.splitAt (len - paddingSz) bin
    paddingWitness = B.replicate paddingSz paddingByte :: Bytes
unpad (ZERO sz) bin
    | not (zeroSizeValid sz) = Nothing
    | len == 0 = Nothing
    | (len `mod` sz) /= 0 = Nothing
    | B.index bin (len - 1) /= 0 = Just bin
    | otherwise = Nothing
  where
    len = B.length bin
