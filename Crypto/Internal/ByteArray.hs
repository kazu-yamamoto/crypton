{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_HADDOCK hide #-}

-- |
-- Module      : Crypto.Internal.ByteArray
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple and efficient byte array types
module Crypto.Internal.ByteArray (
    module Data.ByteArray,
    module Data.ByteArray.Mapping,
    module Data.ByteArray.Encoding,
    constAllZero,
    overCLength,
    inCLengths,
    allocAndFreezePrimIO,
    allocAndFreezePrim,
    bxor,
) where

import Data.ByteArray
import Data.ByteArray.Encoding
import Data.ByteArray.Mapping

import Data.Bits ((.|.))
import Data.Int (Int32)
import qualified Data.Primitive.ByteArray as Prim
import Data.Word (Word32, Word8)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peekByteOff)

import Crypto.Internal.Compat (unsafeDoIO)

-- | Whether a length is too large to reach the C, which takes its lengths as
-- @uint32_t@.
--
-- From 2^32 up the value is truncated on the way down, and the C then works
-- on the low bits of it and leaves the rest of the buffer as it found it --
-- which for a fresh allocation is zeros.  What comes back is as long as the
-- caller asked for, with nothing to say that most of it was never written:
-- a 4 GiB message through Crypto.Cipher.ChaCha.combine came back with 2^32
-- bytes of zeros where the ciphertext should have been.
--
-- Every place that hands a caller's length to the C either turns it away
-- with this or cuts the work into pieces small enough to pass.
--
-- The round trip through 'Word32' rather than a comparison against 2^32,
-- which a 32-bit 'Int' cannot hold.  There every non-negative 'Int' passes,
-- which is the right answer: there is no such buffer to be had.
overCLength :: Int -> Bool
overCLength n = fromIntegral (fromIntegral n :: Word32) /= n

-- | Walk a length in pieces small enough to reach the C, calling the action
-- with the offset and the size of each.
--
-- The same 2 GiB step "Crypto.Hash" has always taken, and for the same
-- reason: the C takes its lengths as @uint32_t@, and a 32-bit 'Int' cannot
-- hold a whole one either.  This is for the C that keeps its state in a
-- context and can simply be called again -- the stream ciphers, the MACs --
-- where a long message can be enciphered in pieces rather than refused.
inCLengths :: Int -> (Int -> Int -> IO ()) -> IO ()
inCLengths total f = go 0
  where
    go !off
        | off >= total = return ()
        | otherwise = f off n >> go (off + n)
      where
        !n = min (total - off) cChunk

-- | The step 'inCLengths' takes: the largest multiple of 64 that a signed
-- 32-bit integer holds.
--
-- Under the 'Int32' bound because a 32-bit 'Int' cannot hold more, and a
-- multiple of 64 because some of the C this feeds -- the AEAD modes -- will
-- take a piece that is not a whole number of blocks only as the last one.
cChunk :: Int
cChunk = 0x7fffffc0

-- | Allocate a pinned 'Prim.ByteArray' of the given size, populate it via a
-- 'Ptr', then freeze and return it.  The pointer must not be retained after
-- the action returns.
allocAndFreezePrimIO :: Int -> (Ptr p -> IO ()) -> IO Prim.ByteArray
allocAndFreezePrimIO n f = do
    mba <- Prim.newPinnedByteArray n
    f (castPtr (Prim.mutableByteArrayContents mba))
    Prim.unsafeFreezeByteArray mba

-- | The allocation is strictly local,
-- the computation is deterministic, and no IO effects escape.
allocAndFreezePrim :: Int -> (Ptr p -> IO ()) -> Prim.ByteArray
allocAndFreezePrim n = unsafeDoIO . allocAndFreezePrimIO n

constAllZero :: ByteArrayAccess ba => ba -> Bool
constAllZero b = unsafeDoIO $ withByteArray b $ \p -> loop p 0 0
  where
    loop :: Ptr b -> Int -> Word8 -> IO Bool
    loop p i !acc
        | i == len = return $! acc == 0
        | otherwise = do
            e <- peekByteOff p i
            loop p (i + 1) (acc .|. e)
    len = Data.ByteArray.length b

-- | @a@ exclusive-ored with @b@, as long as the shorter of the two.
--
-- 'Data.ByteArray.xor' does this a byte at a time through an IO applicative,
-- which allocates about fifty bytes of heap for every byte it produces.  That
-- is more than a block cipher costs: it was four fifths of the time counter
-- mode spent on anything but AES, whose modes are in C and do not come this
-- way.
bxor :: (ByteArrayAccess a, ByteArrayAccess b, ByteArray c) => a -> b -> c
bxor a b = unsafeDoIO $
    alloc n $ \pd ->
        withByteArray a $ \pa ->
            withByteArray b $ \pb ->
                c_memxor pd pa pb (fromIntegral n)
  where
    n = min (Data.ByteArray.length a) (Data.ByteArray.length b)

foreign import ccall unsafe "crypton_memxor.h crypton_memxor"
    c_memxor :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()
