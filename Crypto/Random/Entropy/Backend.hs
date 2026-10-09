-- |
-- Module      : Crypto.Random.Entropy.Backend
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE ExistentialQuantification #-}
module Crypto.Random.Entropy.Backend
    ( EntropyBackend
    , supportedBackends
    , gatherBackend
    , EntropyError(..)
    ) where

import Foreign.Ptr
import Data.Proxy
import Data.Word (Word8)
import Crypto.Random.Entropy.Source
#ifdef WINDOWS
import Crypto.Random.Entropy.Windows
#else
import Crypto.Random.Entropy.SysRandom
import Crypto.Random.Entropy.Unix
#endif

-- | All supported backends, best first.
--
-- The system call comes before everything else: it is the kernel's own
-- generator, it needs no descriptor, and it is what the rest of the world
-- reaches for now.  The device files are what is left when the system has
-- no such call.
--
-- RDRAND is deliberately not here, though it used to be first on x86.  A
-- list like this one is a list of alternatives, and whichever answers
-- first decides the bytes on its own -- which is the one thing #298 says
-- RDRAND should not do.  It still contributes, as one input among others
-- to the seed in @cbits\/crypton_sysdrg.c@, where it goes through SHA-512
-- with the system call's bytes and cannot determine the result by itself.
supportedBackends :: [IO (Maybe EntropyBackend)]
supportedBackends =
    [
#ifndef WINDOWS
    openBackend (Proxy :: Proxy SysRandom),
#endif
#ifdef WINDOWS
    openBackend (Proxy :: Proxy WinCryptoAPI)
#else
    openBackend (Proxy :: Proxy DevRandom), openBackend (Proxy :: Proxy DevURandom)
#endif
    ]

-- | Any Entropy Backend
data EntropyBackend = forall b . EntropySource b => EntropyBackend b

-- | Open a backend handle
openBackend :: EntropySource b => Proxy b -> IO (Maybe EntropyBackend)
openBackend b = fmap EntropyBackend `fmap` callOpen b
  where callOpen :: EntropySource b => Proxy b -> IO (Maybe b)
        callOpen _ = entropyOpen

-- | Gather randomness from an open handle
gatherBackend :: EntropyBackend -- ^ An open Entropy Backend
              -> Ptr Word8      -- ^ Pointer to a buffer to write to
              -> Int            -- ^ number of bytes to write
              -> IO Int         -- ^ return the number of bytes actually written
gatherBackend (EntropyBackend backend) ptr n = entropyGather backend ptr n
