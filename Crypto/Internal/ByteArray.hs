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
    allocAndFreezePrimIO,
    allocAndFreezePrim,
) where

import Data.ByteArray
import Data.ByteArray.Encoding
import Data.ByteArray.Mapping

import Data.Bits ((.|.))
import Data.Word (Word8)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peekByteOff)
import qualified Data.Primitive.ByteArray as Prim

import Crypto.Internal.Compat (unsafeDoIO)

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
