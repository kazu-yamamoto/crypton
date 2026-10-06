-- |
-- Module      : Crypto.Random.Entropy
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.Random.Entropy (
    getEntropy,
) where

import Crypto.Internal.ByteArray (ByteArray)
import qualified Crypto.Internal.ByteArray as B
import System.IO.Unsafe (unsafeInterleaveIO, unsafePerformIO)

import Crypto.Random.Entropy.Unsafe

-- | The backends this system has, worked out once and no further than
-- needed.
--
-- Opening one is not free: for a device file it means opening and closing
-- @\/dev\/random@ or @\/dev\/urandom@ just to learn that it is there.  This
-- used to be done on every call, and for the whole list before any backend
-- was asked for a byte, so a program paid for both devices even when the
-- first backend answered everything.
--
-- Once, now, and lazily: 'replenish' stops as soon as the buffer is full,
-- which leaves the tail of this list unforced, so a system where the first
-- backend answers never opens a device at all.
{-# NOINLINE openedBackends #-}
openedBackends :: [EntropyBackend]
openedBackends = unsafePerformIO (openAsNeeded supportedBackends)
  where
    openAsNeeded [] = return []
    openAsNeeded (o : os) = do
        m <- o
        rest <- unsafeInterleaveIO (openAsNeeded os)
        return $ maybe rest (: rest) m

-- | Get some entropy from the system source of entropy
getEntropy :: ByteArray byteArray => Int -> IO byteArray
getEntropy n = B.alloc n (replenish n openedBackends)
