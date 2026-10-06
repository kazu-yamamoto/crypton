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
    ) where

import Foreign.Ptr
import Data.Proxy
import Data.Word (Word8)
import Crypto.Random.Entropy.Source
#ifdef SUPPORT_RDRAND
import Crypto.Random.Entropy.RDRand
#endif
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
-- reaches for now.  RDRAND and the device files are what is left when the
-- system has no such call.
supportedBackends :: [IO (Maybe EntropyBackend)]
supportedBackends =
    [
#ifndef WINDOWS
    openBackend (Proxy :: Proxy SysRandom),
#endif
#ifdef SUPPORT_RDRAND
    openBackend (Proxy :: Proxy RDRand),
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
