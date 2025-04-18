{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module      : Crypto.Hash.Blake2bp
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Module containing the binding functions to work with the
-- Blake2bp cryptographic hash.
module Crypto.Hash.Blake2bp (
    Blake2bp_512 (..),
) where

import Crypto.Hash.Types
import Data.Data
import Data.Word (Word32, Word8)
import Foreign.Ptr (Ptr)

-- | Blake2bp (512 bits) cryptographic hash algorithm
data Blake2bp_512 = Blake2bp_512
    deriving (Show, Data)

instance HashAlgorithm Blake2bp_512 where
    type HashBlockSize Blake2bp_512 = 128
    type HashDigestSize Blake2bp_512 = 64
    type HashInternalContextSize Blake2bp_512 = 1768
    hashBlockSize _ = 128
    hashDigestSize _ = 64
    hashInternalContextSize _ = 1768
    hashInternalInit p = c_blake2bp_init p 512
    hashInternalUpdate = c_blake2bp_update
    hashInternalFinalize p = c_blake2bp_finalize p 512

foreign import ccall unsafe "crypton_blake2bp_init"
    c_blake2bp_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "crypton_blake2bp_update"
    c_blake2bp_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "crypton_blake2bp_finalize"
    c_blake2bp_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
