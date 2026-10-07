-- |
-- Module      : Crypto.Random.Entropy.Unsafe
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.Random.Entropy.Unsafe (
    replenish,
    module Crypto.Random.Entropy.Backend,
) where

import Control.Exception (throwIO)

import Crypto.Random.Entropy.Backend
import Data.Word (Word8)
import Foreign.Ptr (Ptr, plusPtr)

-- | Refill the entropy in a buffer
--
-- Call each entropy backend in turn until the buffer has been replenished.
--
-- Throws 'EntropyError': 'NoEntropySource' when there is no backend at all,
-- and 'EntropyShort' when three passes over the backends still leave the
-- buffer unfilled.
replenish :: Int -> [EntropyBackend] -> Ptr Word8 -> IO ()
replenish _ [] _ = throwIO NoEntropySource
replenish poolSize backends ptr = loop 0 backends ptr poolSize
  where
    loop :: Int -> [EntropyBackend] -> Ptr Word8 -> Int -> IO ()
    loop _ _ _ 0 = return ()
    loop retry [] p n
        | retry == 3 = throwIO $ EntropyShort poolSize (poolSize - n)
        | otherwise = loop (retry + 1) backends p n
    loop retry (b : bs) p n = do
        r <- gatherBackend b p n
        loop retry bs (p `plusPtr` r) (n - r)
