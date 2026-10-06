{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Random.Entropy.SysRandom
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : Unix
--
-- The kernel's own generator, reached without a file descriptor:
-- @getrandom(2)@ on Linux and FreeBSD, @getentropy(3)@ where that is what
-- the system has.
--
-- This is the source to prefer over reading @\/dev\/urandom@.  It needs no
-- path and no descriptor, so it still answers where @\/dev@ is not mounted
-- or not populated, and it cannot be defeated by a full descriptor table.
module Crypto.Random.Entropy.SysRandom (
    SysRandom,
) where

import Crypto.Random.Entropy.Source
import Data.Word (Word8)
import Foreign.C.Types
import Foreign.Ptr

-- Both are @safe@ rather than @unsafe@: at early boot, before the kernel
-- pool is initialised, these calls block, and an unsafe call that blocks
-- holds the capability it runs on.
foreign import ccall safe "crypton_sysrandom_available"
    c_sysrandom_available :: IO CInt

foreign import ccall safe "crypton_sysrandom_bytes"
    c_sysrandom_bytes :: Ptr Word8 -> CInt -> IO CInt

-- | The system call, where there is one.
data SysRandom = SysRandom

instance EntropySource SysRandom where
    -- Asked at run time and not only at compile time: a binary built where
    -- the header declares the call can still run on a kernel that answers
    -- ENOSYS.
    entropyOpen = available `fmap` c_sysrandom_available
      where
        available 0 = Nothing
        available _ = Just SysRandom

    entropyGather _ ptr n =
        fromIntegral `fmap` c_sysrandom_bytes ptr (fromIntegral n)

    entropyClose _ = return ()
