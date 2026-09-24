{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

-- |
-- Module      : Crypto.Hash.Skein256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Module containing the binding functions to work with the
-- Skein256 cryptographic hash.
module Crypto.Hash.Skein256 (
    Skein256 (..),
    Skein256_224 (..),
    Skein256_256 (..),
) where

import Crypto.Hash.Types
import Crypto.Internal.Nat
import Data.Data
import Data.Word (Word32, Word8)
import Foreign.Ptr (Ptr)
import GHC.TypeLits (KnownNat, Nat, type (+))

-- | Skein256 (224 bits) cryptographic hash algorithm
data Skein256_224 = Skein256_224
    deriving (Show, Data)

instance HashAlgorithm Skein256_224 where
    type HashBlockSize Skein256_224 = 32
    type HashDigestSize Skein256_224 = 28
    type HashInternalContextSize Skein256_224 = 96
    hashBlockSize _ = 32
    hashDigestSize _ = 28
    hashInternalContextSize _ = 96
    hashInternalInit p = c_skein256_init p 224
    hashInternalUpdate = c_skein256_update
    hashInternalFinalize p = c_skein256_finalize p 224

-- | Skein256 (256 bits) cryptographic hash algorithm
data Skein256_256 = Skein256_256
    deriving (Show, Data)

instance HashAlgorithm Skein256_256 where
    type HashBlockSize Skein256_256 = 32
    type HashDigestSize Skein256_256 = 32
    type HashInternalContextSize Skein256_256 = 96
    hashBlockSize _ = 32
    hashDigestSize _ = 32
    hashInternalContextSize _ = 96
    hashInternalInit p = c_skein256_init p 256
    hashInternalUpdate = c_skein256_update
    hashInternalFinalize p = c_skein256_finalize p 256

-- | Skein256 with the digest size given as a type parameter of kind 'Nat',
-- in bits.  @t'Skein256' 256@ is @t'Skein256_256'@; the sizes with a type of
-- their own
-- above are there for their names, and this one also takes the sizes that
-- have none.
--
-- A size that is not a whole number of bytes is rounded up to the next one,
-- as the implementation underneath does.
--
-- The output is produced in counter mode, a block of it per Threefish call,
-- so one large digest is a good deal cheaper than the same number of bytes
-- taken from repeated small ones: on an Apple M4, 512 KiB arrives at 947 MB/s
-- in one digest against 172 MB/s as 8192 separate @t'Skein256_256'@ ones.
--
-- Note the digest size goes into the configuration block, so it changes the
-- value the message is hashed from: a longer digest is /not/ an extension of
-- a shorter one.  That is the opposite of how t'Crypto.Hash.SHAKE.SHAKE128'
-- behaves.
data Skein256 (bitlen :: Nat) = Skein256
    deriving (Show, Data)

instance KnownNat bitlen => HashAlgorithm (Skein256 bitlen) where
    type HashBlockSize (Skein256 bitlen) = 32
    type HashDigestSize (Skein256 bitlen) = Div8 (bitlen + 7)
    type HashInternalContextSize (Skein256 bitlen) = 96
    hashBlockSize _ = 32
    hashDigestSize _ = byteLen (Proxy :: Proxy bitlen)
    hashInternalContextSize _ = 96
    hashInternalInit p = c_skein256_init p (integralNatVal (Proxy :: Proxy bitlen))
    hashInternalUpdate = c_skein256_update
    hashInternalFinalize p = c_skein256_finalize p (integralNatVal (Proxy :: Proxy bitlen))

foreign import ccall unsafe "crypton_skein256_init"
    c_skein256_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "crypton_skein256_update"
    c_skein256_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "crypton_skein256_finalize"
    c_skein256_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
