{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

-- |
-- Module      : Crypto.Hash.Skein512
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Module containing the binding functions to work with the
-- Skein512 cryptographic hash.
module Crypto.Hash.Skein512 (
    Skein512 (..),
    Skein512_224 (..),
    Skein512_256 (..),
    Skein512_384 (..),
    Skein512_512 (..),
) where

import Crypto.Hash.Types
import Crypto.Internal.Nat
import Data.Data
import Data.Word (Word32, Word8)
import Foreign.Ptr (Ptr)
import GHC.TypeLits (KnownNat, Nat, type (+))

-- | Skein512 (224 bits) cryptographic hash algorithm
data Skein512_224 = Skein512_224
    deriving (Show, Data)

instance HashAlgorithm Skein512_224 where
    type HashBlockSize Skein512_224 = 64
    type HashDigestSize Skein512_224 = 28
    type HashInternalContextSize Skein512_224 = 160
    hashBlockSize _ = 64
    hashDigestSize _ = 28
    hashInternalContextSize _ = 160
    hashInternalInit p = c_skein512_init p 224
    hashInternalUpdate = c_skein512_update
    hashInternalFinalize p = c_skein512_finalize p 224

-- | Skein512 (256 bits) cryptographic hash algorithm
data Skein512_256 = Skein512_256
    deriving (Show, Data)

instance HashAlgorithm Skein512_256 where
    type HashBlockSize Skein512_256 = 64
    type HashDigestSize Skein512_256 = 32
    type HashInternalContextSize Skein512_256 = 160
    hashBlockSize _ = 64
    hashDigestSize _ = 32
    hashInternalContextSize _ = 160
    hashInternalInit p = c_skein512_init p 256
    hashInternalUpdate = c_skein512_update
    hashInternalFinalize p = c_skein512_finalize p 256

-- | Skein512 (384 bits) cryptographic hash algorithm
data Skein512_384 = Skein512_384
    deriving (Show, Data)

instance HashAlgorithm Skein512_384 where
    type HashBlockSize Skein512_384 = 64
    type HashDigestSize Skein512_384 = 48
    type HashInternalContextSize Skein512_384 = 160
    hashBlockSize _ = 64
    hashDigestSize _ = 48
    hashInternalContextSize _ = 160
    hashInternalInit p = c_skein512_init p 384
    hashInternalUpdate = c_skein512_update
    hashInternalFinalize p = c_skein512_finalize p 384

-- | Skein512 (512 bits) cryptographic hash algorithm
data Skein512_512 = Skein512_512
    deriving (Show, Data)

instance HashAlgorithm Skein512_512 where
    type HashBlockSize Skein512_512 = 64
    type HashDigestSize Skein512_512 = 64
    type HashInternalContextSize Skein512_512 = 160
    hashBlockSize _ = 64
    hashDigestSize _ = 64
    hashInternalContextSize _ = 160
    hashInternalInit p = c_skein512_init p 512
    hashInternalUpdate = c_skein512_update
    hashInternalFinalize p = c_skein512_finalize p 512

-- | Skein512 with the digest size given as a type parameter of kind 'Nat',
-- in bits.  @t'Skein512' 512@ is @t'Skein512_512'@; the sizes with a type of
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
-- in one digest against 172 MB/s as 8192 separate @t'Skein512_512'@ ones.
--
-- Note the digest size goes into the configuration block, so it changes the
-- value the message is hashed from: a longer digest is /not/ an extension of
-- a shorter one.  That is the opposite of how t'Crypto.Hash.SHAKE.SHAKE128'
-- behaves.
data Skein512 (bitlen :: Nat) = Skein512
    deriving (Show, Data)

instance KnownNat bitlen => HashAlgorithm (Skein512 bitlen) where
    type HashBlockSize (Skein512 bitlen) = 64
    type HashDigestSize (Skein512 bitlen) = Div8 (bitlen + 7)
    type HashInternalContextSize (Skein512 bitlen) = 160
    hashBlockSize _ = 64
    hashDigestSize _ = byteLen (Proxy :: Proxy bitlen)
    hashInternalContextSize _ = 160
    hashInternalInit p = c_skein512_init p (integralNatVal (Proxy :: Proxy bitlen))
    hashInternalUpdate = c_skein512_update
    hashInternalFinalize p = c_skein512_finalize p (integralNatVal (Proxy :: Proxy bitlen))

foreign import ccall unsafe "crypton_skein512_init"
    c_skein512_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "crypton_skein512_update"
    c_skein512_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "crypton_skein512_finalize"
    c_skein512_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
