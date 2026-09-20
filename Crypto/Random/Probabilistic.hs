-- |
-- Module      : Crypto.Random.Probabilistic
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.Random.Probabilistic (
    probabilisticFrom,
) where

import Crypto.Hash (SHA512 (..), hashWith)
import Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat
import Crypto.Random
import Crypto.Random.ChaChaDRG (initialize)

-- | Run a probabilistic algorithm on a generator derived from the value it is
-- about to work on, and from a secret this process drew once.
--
-- This is useful for a probabilistic algorithm like the Miller-Rabin primality
-- test, where the caller is a pure function and has to behave like one: the
-- same value has to give the same answer for as long as the process lives.
-- Deriving the generator from the value gives that much, and it keeps the
-- draws made for two different values independent of each other -- one
-- generator made once and shared by every call would make the witnesses drawn
-- for one value the witnesses for every value.
--
-- The process secret is what makes the derivation unpredictable.  The values
-- worked on may come from wherever the caller's input comes from, so the
-- generator must not be something that can be worked out from them.
--
-- The IO is not exposed and the result is not reproducible between processes.
-- Generally, it's advised not to use this function.
probabilisticFrom
    :: ByteArrayAccess seed
    => seed
    -- ^ the value being worked on, as bytes
    -> MonadPseudoRandom ChaChaDRG a
    -> a
probabilisticFrom material f = fst $ withDRG drg f
  where
    drg = initialize (B.take seedLength (B.convert digest :: ScrubbedBytes))
    digest = hashWith SHA512 (B.append secret (B.convert material) :: ScrubbedBytes)
    -- what Crypto.Random.ChaChaDRG.initialize wants, and no more than SHA-512
    -- produces
    seedLength = 40

-- | Drawn once, for the lifetime of the process: it is the only part of the
-- derivation above that an attacker supplying values cannot see.
secret :: ScrubbedBytes
secret = unsafeDoIO (getRandomBytes 32)
{-# NOINLINE secret #-}
