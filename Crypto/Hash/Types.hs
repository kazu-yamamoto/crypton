{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module      : Crypto.Hash.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Crypto hash types definitions
module Crypto.Hash.Types (
    HashAlgorithm (..),
    HashAlgorithmPrefix (..),
    Context (..),
    Digest (..),
) where

import Control.DeepSeq (deepseq)
import Control.Monad.Primitive (PrimMonad (..))
import Control.Monad.ST
import Crypto.Internal.ByteArray (ByteArrayAccess (..), Bytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Imports
import Data.Base16.Types (extractBase16)
import Data.ByteString (ByteString)
import Data.ByteString.Base16 (encodeBase16)
import Data.Char (digitToInt, isHexDigit)
import Data.Data (Data)
import Data.Primitive.ByteArray (
    ByteArray,
    MutableByteArray,
    newPinnedByteArray,
    sizeofByteArray,
    unsafeFreezeByteArray,
    withByteArrayContents,
    writeByteArray,
 )
import qualified Data.Text as Text
import Foreign.Ptr (Ptr, castPtr)
import GHC.TypeLits (Nat)

-- | Class representing hashing algorithms.
--
-- The interface presented here is update in place
-- and lowlevel. the Hash module takes care of
-- hidding the mutable interface properly.
class HashAlgorithm a where
    -- | Associated type for the block size of the hash algorithm
    type HashBlockSize a :: Nat

    -- | Associated type for the digest size of the hash algorithm
    type HashDigestSize a :: Nat

    -- | Associated type for the internal context size of the hash algorithm
    type HashInternalContextSize a :: Nat

    -- | Get the block size of a hash algorithm
    hashBlockSize :: a -> Int

    -- | Get the digest size of a hash algorithm
    hashDigestSize :: a -> Int

    -- | Get the size of the context used for a hash algorithm
    hashInternalContextSize :: a -> Int

    -- hashAlgorithmFromProxy  :: Proxy a -> a

    -- | Initialize a context pointer to the initial state of a hash algorithm
    hashInternalInit :: Ptr (Context a) -> IO ()

    -- | Update the context with some raw data
    hashInternalUpdate :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

    -- | Finalize the context and set the digest raw memory to the right value
    hashInternalFinalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()

-- | Hashing algorithms with a constant-time implementation.
class HashAlgorithm a => HashAlgorithmPrefix a where
    -- | Update the context with the first N bytes of a buffer and finalize this
    -- context.  The code path executed is independent from N and depends only
    -- on the complete buffer length.
    hashInternalFinalizePrefix
        :: Ptr (Context a)
        -> Ptr Word8
        -> Word32
        -> Word32
        -> Ptr (Digest a)
        -> IO ()

{-
hashContextGetAlgorithm :: HashAlgorithm a => Context a -> a
hashContextGetAlgorithm = undefined
-}

-- | Represent a context for a given hash algorithm.
--
-- This type is an instance of 'ByteArrayAccess' for debugging purpose. Internal
-- layout is architecture dependent, may contain uninitialized data fragments,
-- and change in future versions.  The bytearray should not be used as input to
-- cryptographic algorithms.
--
-- __A context is not erased when it is finished with.__  A hash algorithm
-- buffers its input a block at a time, and finalizing does not clear what is
-- left there.  How much survives depends on where the message ended relative
-- to the block: with SHA-256, a 32-byte message is still in the context in
-- full afterwards, and a 100-byte one leaves its last 36 bytes.
-- @hashFinalize@ works on a copy, so the caller's own context keeps what it
-- had as well.  Nothing clears either of them: this is 'Bytes' rather than
-- @ScrubbedBytes@, and the C clears nothing.  They go to the garbage
-- collector as they are, and a core file, a crash dump or a swapped page can
-- carry them away afterwards.
--
-- That is a deliberate trade rather than an oversight, and there is no way
-- to ask for the other side of it: no operation here clears a context.
-- Scrubbing them all was measured at about 70% of a 32-byte hash and a third
-- of an incremental one, because the allocation is most of the work when the
-- message is short -- and short hashes are the common case, in HMAC, in
-- HKDF, and anywhere a key or an identifier is hashed.  A 64 KB hash does
-- not notice it.  Anything that must not be left in memory this way is
-- better not hashed through this interface at all.
newtype Context a = Context Bytes
    deriving (ByteArrayAccess, NFData)

-- | Represent a digest for a given hash algorithm.
--
-- This type is an instance of 'ByteArrayAccess' from package
-- <https://hackage.haskell.org/package/ram ram>.
-- Module "Data.ByteArray" provides many primitives to work with those values
-- including conversion to other types.
--
-- Creating a digest from a bytearray is also possible with function
-- 'Crypto.Hash.digestFromByteString'.
newtype Digest a = Digest ByteArray
    deriving (Eq, Ord, Data)

type role Digest nominal

instance NFData (Digest a) where
    rnf (Digest u) = u `deepseq` ()

instance ByteArrayAccess (Digest a) where
    length (Digest ba) = sizeofByteArray ba
    withByteArray (Digest ba) f = withByteArrayContents ba (f . castPtr)

instance Show (Digest a) where
    show d =
        Text.unpack (extractBase16 $ encodeBase16 (B.convert d :: ByteString))

instance HashAlgorithm a => Read (Digest a) where
    readsPrec _ str = runST $ do
        mut <- newPinnedByteArray len
        loop len mut len str
      where
        len = hashDigestSize (undefined :: a)

loop
    :: Int
    -> MutableByteArray (PrimState (ST s))
    -> Int
    -> String
    -> ST s [(Digest a, String)]
loop _ mut 0 cs = (\b -> [(Digest b, cs)]) <$> unsafeFreezeByteArray mut
loop _ _ _ [] = return []
loop _ _ _ [_] = return []
loop len mut n (c : (d : ds))
    | not (isHexDigit c) = return []
    | not (isHexDigit d) = return []
    | otherwise = do
        let w8 :: Word8
            w8 = fromIntegral $ digitToInt c * 16 + digitToInt d
        writeByteArray mut (len - n) w8
        loop len mut (n - 1) ds
