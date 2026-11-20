{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Crypto.MAC.HMAC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Provide the HMAC (Hash based Message Authentication Code) base algorithm.
-- <http://en.wikipedia.org/wiki/HMAC>
module Crypto.MAC.HMAC (
    hmac,
    hmacLazy,
    HMAC (..),

    -- * Incremental
    Context (..),
    initialize,
    update,
    updates,
    finalize,
) where

import Crypto.Hash hiding (Context)
import qualified Crypto.Hash as Hash (Context)
import Crypto.Hash.IO
import Crypto.Hash.Types (Digest (..), updateBlocks)
import Crypto.Internal.ByteArray (
    ByteArrayAccess,
    ScrubbedBytes,
    allocAndFreezePrim,
 )
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat
import Data.Bits (xor)
import qualified Data.ByteString.Lazy as L
import Data.Memory.PtrMethods
import Data.Word (Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr)

-- | Represent an HMAC that is a phantom type with the hash used to produce the mac.
--
-- The Eq instance is constant time.  No Show instance is provided, to avoid
-- printing by mistake.
newtype HMAC a = HMAC {hmacGetDigest :: Digest a}
    deriving (ByteArrayAccess)

instance Eq (HMAC a) where
    (HMAC b1) == (HMAC b2) = B.constEq b1 b2

-- | Compute a MAC using the supplied hashing function
hmac
    :: (ByteArrayAccess key, ByteArrayAccess message, HashAlgorithm a)
    => key
    -- ^ Secret key
    -> message
    -- ^ Message to MAC
    -> HMAC a
hmac secret msg = hmacChunks secret [msg]

-- | Compute a MAC using the supplied hashing function, for a lazy input
hmacLazy
    :: (ByteArrayAccess key, HashAlgorithm a)
    => key
    -- ^ Secret key
    -> L.ByteString
    -- ^ Message to MAC
    -> HMAC a
hmacLazy secret msg = hmacChunks secret (L.toChunks msg)

-- | HMAC in one pass over one hash context and one key block, both used in
-- place and wiped afterwards.  Going through 'initialize' and 'finalize'
-- builds and copies contexts, which costs several times the hashing itself
-- on a short message.
hmacChunks
    :: forall key message a
     . (ByteArrayAccess key, ByteArrayAccess message, HashAlgorithm a)
    => key -> [message] -> HMAC a
hmacChunks secret msgs = HMAC $
    Digest $
        allocAndFreezePrim dsize $ \(dig :: Ptr (Digest a)) ->
            allocaBytes csize $ \(ctx :: Ptr (Hash.Context a)) ->
                allocaBytes bsize $ \(pad :: Ptr Word8) -> do
                    -- the key block: the key, or its digest when it is longer
                    -- than a block, padded with zeros
                    memSet pad 0 bsize
                    B.withByteArray secret $ \k ->
                        if klen > bsize
                            then do
                                hashInternalInit ctx
                                updateBlocks ctx klen k
                                hashInternalFinalize ctx dig
                                memCopy pad (castPtr dig) (min dsize bsize)
                            else memCopy pad k klen
                    memXorWith pad 0x36 pad bsize
                    hashInternalInit ctx
                    updateBlocks ctx bsize pad
                    mapM_ (\m -> B.withByteArray m $ updateBlocks ctx (B.length m)) msgs
                    hashInternalFinalize ctx dig
                    memXorWith pad (0x36 `xor` 0x5c) pad bsize
                    hashInternalInit ctx
                    updateBlocks ctx bsize pad
                    updateBlocks ctx dsize (castPtr dig)
                    hashInternalFinalize ctx dig
                    memSet pad 0 bsize
                    memSet (castPtr ctx) 0 csize
  where
    klen = B.length secret
    bsize = hashBlockSize (undefined :: a)
    dsize = hashDigestSize (undefined :: a)
    csize = hashInternalContextSize (undefined :: a)

-- | Represent an ongoing HMAC state, that can be appended with 'update'
-- and finalize to an HMAC with 'finalize'
data Context hashalg = Context !(Hash.Context hashalg) !(Hash.Context hashalg)

-- | Initialize a new incremental HMAC context
initialize
    :: (ByteArrayAccess key, HashAlgorithm a)
    => key
    -- ^ Secret key
    -> Context a
initialize secret = unsafeDoIO (doHashAlg undefined)
  where
    doHashAlg :: HashAlgorithm a => a -> IO (Context a)
    doHashAlg alg = do
        !withKey <- case B.length secret `compare` blockSize of
            EQ -> return $ B.withByteArray secret
            LT -> do
                key <- B.alloc blockSize $ \k -> do
                    memSet k 0 blockSize
                    B.withByteArray secret $ \s -> memCopy k s (B.length secret)
                return $ B.withByteArray (key :: ScrubbedBytes)
            GT -> do
                -- hash the secret key
                ctx <- hashMutableInitWith alg
                hashMutableUpdate ctx secret
                digest <- hashMutableFinalize ctx
                hashMutableReset ctx
                -- pad it if necessary
                if digestSize < blockSize
                    then do
                        key <- B.alloc blockSize $ \k -> do
                            memSet k 0 blockSize
                            B.withByteArray digest $ \s -> memCopy k s (B.length digest)
                        return $ B.withByteArray (key :: ScrubbedBytes)
                    else
                        return $ B.withByteArray digest
        (inner, outer) <- withKey $ \keyPtr ->
            (,)
                <$> B.alloc blockSize (\p -> memXorWith p 0x36 keyPtr blockSize)
                <*> B.alloc blockSize (\p -> memXorWith p 0x5c keyPtr blockSize)
        return $
            Context
                (hashUpdates initCtx [outer :: ScrubbedBytes])
                (hashUpdates initCtx [inner :: ScrubbedBytes])
      where
        blockSize = hashBlockSize alg
        digestSize = hashDigestSize alg
        initCtx = hashInitWith alg
{-# NOINLINE initialize #-}

-- | Incrementally update a HMAC context
update
    :: (ByteArrayAccess message, HashAlgorithm a)
    => Context a
    -- ^ Current HMAC context
    -> message
    -- ^ Message to append to the MAC
    -> Context a
    -- ^ Updated HMAC context
update (Context octx ictx) msg =
    Context octx (hashUpdate ictx msg)

-- | Incrementally update a HMAC context with multiple inputs
updates
    :: (ByteArrayAccess message, HashAlgorithm a)
    => Context a
    -- ^ Current HMAC context
    -> [message]
    -- ^ Messages to append to the MAC
    -> Context a
    -- ^ Updated HMAC context
updates (Context octx ictx) msgs =
    Context octx (hashUpdates ictx msgs)

-- | Finalize a HMAC context and return the HMAC.
finalize
    :: HashAlgorithm a
    => Context a
    -> HMAC a
finalize (Context octx ictx) =
    HMAC $ hashFinalize $ hashUpdates octx [hashFinalize ictx]
