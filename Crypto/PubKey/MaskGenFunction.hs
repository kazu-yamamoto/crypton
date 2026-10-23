{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Crypto.PubKey.MaskGenFunction
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.PubKey.MaskGenFunction (
    MaskGenAlgorithm,
    mgf1,
) where

import Control.Monad (forM_)
import Crypto.Hash (Context, Digest)
import Crypto.Hash.IO (HashAlgorithm (..))
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import Data.Bits (shiftR)
import Data.Word (Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (pokeByteOff)

-- | Represent a mask generation algorithm
type MaskGenAlgorithm seed output =
    seed
    -- ^ seed
    -> Int
    -- ^ length to generate
    -> output

-- | Mask generation algorithm MGF1
mgf1
    :: forall seed output hashAlg
     . (ByteArrayAccess seed, ByteArray output, HashAlgorithm hashAlg)
    => hashAlg
    -> seed
    -> Int
    -> output
mgf1 hashAlg seed len
    | len <= 0 = B.empty
    | otherwise = B.allocAndFreeze len $ \out ->
        -- the seeded context is kept, and copied for each block rather than
        -- rebuilt; each block's digest is written straight into the output
        allocaBytes ctxSize $ \(seeded :: Ptr (Context hashAlg)) ->
            allocaBytes ctxSize $ \(ctx :: Ptr (Context hashAlg)) ->
                allocaBytes digestLen $ \(dig :: Ptr (Digest hashAlg)) ->
                    allocaBytes 4 $ \(cnt :: Ptr Word8) -> do
                        hashInternalInit seeded
                        B.withByteArray seed $ \p ->
                            hashInternalUpdate seeded p (fromIntegral (B.length seed))
                        forM_ [0 .. maxCounter - 1] $ \i -> do
                            copyBytes ctx seeded ctxSize
                            forM_ [0 .. 3] $ \k ->
                                pokeByteOff cnt k (fromIntegral (i `shiftR` (8 * (3 - k))) :: Word8)
                            hashInternalUpdate ctx cnt 4
                            hashInternalFinalize ctx dig
                            let off = i * digestLen
                            copyBytes (out `plusPtr` off) (castPtr dig) (min digestLen (len - off))
  where
    ctxSize = hashInternalContextSize hashAlg
    digestLen = hashDigestSize hashAlg
    maxCounter = (len + digestLen - 1) `div` digestLen
