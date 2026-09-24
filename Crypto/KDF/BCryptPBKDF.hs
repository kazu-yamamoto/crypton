-- |
-- Module      : Crypto.KDF.BCryptPBKDF
-- License     : BSD-style
-- Stability   : experimental
-- Portability : Good
--
-- Port of the bcrypt_pbkdf key derivation function from OpenBSD
-- as described at <http://man.openbsd.org/bcrypt_pbkdf.3>.
module Crypto.KDF.BCryptPBKDF (
    Parameters (..),
    generate,
    tryGenerate,
    hashInternal,
    tryHashInternal,
)
where

import qualified Control.Exception as E
import Control.Monad (when)
import Crypto.Cipher.Blowfish.Primitive (bcryptPbkdfHash)
import Crypto.Error
import Crypto.Hash.Algorithms (SHA512 (..))
import Crypto.Hash.Types (
    Context,
    hashDigestSize,
    hashInternalContextSize,
    hashInternalFinalize,
    hashInternalInit,
    hashInternalUpdate,
 )
import Crypto.Internal.Compat (unsafeDoIO)
import Data.Bits
import qualified Data.ByteArray as B
import qualified Data.ByteString.Internal as BSI
import Data.Foldable (forM_)
import Data.Memory.PtrMethods (memCopy, memSet, memXor)
import Data.Word
import Foreign.ForeignPtr (ForeignPtr, mallocForeignPtrBytes, withForeignPtr)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

data Parameters = Parameters
    { iterCounts :: Int
    -- ^ The number of user-defined iterations for the algorithm
    --   (must be > 0)
    , outputLength :: Int
    -- ^ The number of bytes to generate out of BCryptPBKDF
    --   (must be in 1..1024)
    }
    deriving (Eq, Ord, Show)

-- | Derive a key of specified length using the bcrypt_pbkdf algorithm.
--
-- Parameters outside the ranges documented for t'Parameters' raise
-- 'CryptoError_ParameterInvalid'; 'tryGenerate' reports the same condition as
-- 'CryptoFailed'.
generate
    :: (B.ByteArray pass, B.ByteArray salt, B.ByteArray output)
    => Parameters
    -> pass
    -> salt
    -> output
generate params pass salt = throwCryptoError (tryGenerate params pass salt)

-- | Derive a key of specified length using the bcrypt_pbkdf algorithm,
-- reporting parameters the implementation refuses rather than raising.
tryGenerate
    :: (B.ByteArray pass, B.ByteArray salt, B.ByteArray output)
    => Parameters
    -> pass
    -> salt
    -> CryptoFailable output
tryGenerate params pass salt
    | iterCounts params < 1 = CryptoFailed CryptoError_ParameterInvalid
    | keyLen < 1 || keyLen > 1024 = CryptoFailed CryptoError_ParameterInvalid
    | otherwise = CryptoPassed $ B.unsafeCreate keyLen deriveKey
  where
    outLen, tmpLen, blkLen, keyLen, passLen, saltLen, ctxLen, hashLen, blocks :: Int
    outLen = 32
    tmpLen = 32
    blkLen = 4
    passLen = B.length pass
    saltLen = B.length salt
    keyLen = outputLength params
    ctxLen = hashInternalContextSize SHA512
    hashLen = hashDigestSize SHA512 -- 64
    blocks = (keyLen + outLen - 1) `div` outLen

    deriveKey :: Ptr Word8 -> IO ()
    deriveKey keyPtr = do
        -- Allocate all necessary memory. The algorithm shall not allocate
        -- any more dynamic memory after this point. ForeignPtrs allocate
        -- pinned memory, so raw pointers to them are stable.
        ctxFP <- mallocForeignPtrBytes ctxLen :: IO (ForeignPtr Word8)
        outFP <- mallocForeignPtrBytes outLen :: IO (ForeignPtr Word8)
        tmpFP <- mallocForeignPtrBytes tmpLen :: IO (ForeignPtr Word8)
        blkFP <- mallocForeignPtrBytes blkLen :: IO (ForeignPtr Word8)
        passHashFP <- mallocForeignPtrBytes hashLen :: IO (ForeignPtr Word8)
        saltHashFP <- mallocForeignPtrBytes hashLen :: IO (ForeignPtr Word8)
        -- Finally erase all memory areas that contain information from
        -- which the derived key could be reconstructed.
        finallyErase outFP outLen $
            finallyErase passHashFP hashLen $
                B.withByteArray pass $ \passPtr ->
                    B.withByteArray salt $ \saltPtr ->
                        withForeignPtr ctxFP $ \ctxPtr' ->
                            withForeignPtr outFP $ \outPtr ->
                                withForeignPtr tmpFP $ \tmpPtr ->
                                    withForeignPtr blkFP $ \blkPtr ->
                                        withForeignPtr passHashFP $ \passHashPtr ->
                                            withForeignPtr saltHashFP $ \saltHashPtr -> do
                                                -- Hash the password.
                                                let shaPtr = castPtr ctxPtr' :: Ptr (Context SHA512)
                                                hashInternalInit shaPtr
                                                hashInternalUpdate shaPtr passPtr (fromIntegral passLen)
                                                hashInternalFinalize shaPtr (castPtr passHashPtr)
                                                -- Create a stable ByteString view of the password hash
                                                -- (passHashFP is not modified after this point).
                                                let passHashBS = BSI.fromForeignPtr passHashFP 0 hashLen
                                                forM_ [1 .. blocks] $ \block -> do
                                                    -- Poke the increased block counter.
                                                    pokeByteOff blkPtr 0 (fromIntegral (block `shiftR` 24) :: Word8)
                                                    pokeByteOff blkPtr 1 (fromIntegral (block `shiftR` 16) :: Word8)
                                                    pokeByteOff blkPtr 2 (fromIntegral (block `shiftR` 8) :: Word8)
                                                    pokeByteOff blkPtr 3 (fromIntegral (block `shiftR` 0 :: Int) :: Word8)
                                                    -- First round (slightly different).
                                                    hashInternalInit shaPtr
                                                    hashInternalUpdate shaPtr saltPtr (fromIntegral saltLen)
                                                    hashInternalUpdate shaPtr blkPtr (fromIntegral blkLen)
                                                    hashInternalFinalize shaPtr (castPtr saltHashPtr)
                                                    let saltHashBS = BSI.fromForeignPtr saltHashFP 0 hashLen
                                                    hashInternalMutable passHashBS saltHashBS tmpPtr
                                                    memCopy outPtr tmpPtr outLen
                                                    -- Remaining rounds.
                                                    forM_ [2 .. iterCounts params] $ const $ do
                                                        hashInternalInit shaPtr
                                                        hashInternalUpdate shaPtr tmpPtr (fromIntegral tmpLen)
                                                        hashInternalFinalize shaPtr (castPtr saltHashPtr)
                                                        let saltHashBS2 = BSI.fromForeignPtr saltHashFP 0 hashLen
                                                        hashInternalMutable passHashBS saltHashBS2 tmpPtr
                                                        memXor outPtr outPtr tmpPtr outLen
                                                    -- Spread the current out buffer evenly over the key buffer.
                                                    -- After both loops have run every byte of the key buffer
                                                    -- will have been written to exactly once and every byte
                                                    -- of the output will have been used.
                                                    forM_ [0 .. outLen - 1] $ \outIdx -> do
                                                        let keyIdx = outIdx * blocks + block - 1
                                                        when (keyIdx < keyLen) $ do
                                                            w8 <- peekByteOff outPtr outIdx :: IO Word8
                                                            pokeByteOff keyPtr keyIdx w8

-- | Internal hash function used by `generate`.
--
-- Normal users should not need this.
--
-- Inputs that are not 512 bits long raise 'CryptoError_ParameterInvalid';
-- 'tryHashInternal' reports the same condition as 'CryptoFailed'.
hashInternal
    :: (B.ByteArrayAccess pass, B.ByteArrayAccess salt, B.ByteArray output)
    => pass
    -> salt
    -> output
hashInternal passHash saltHash =
    throwCryptoError (tryHashInternal passHash saltHash)

-- | Internal hash function used by 'tryGenerate', reporting inputs the
-- implementation refuses rather than raising.
--
-- Normal users should not need this.
tryHashInternal
    :: (B.ByteArrayAccess pass, B.ByteArrayAccess salt, B.ByteArray output)
    => pass
    -> salt
    -> CryptoFailable output
tryHashInternal passHash saltHash
    | B.length passHash /= 64 = CryptoFailed CryptoError_ParameterInvalid
    | B.length saltHash /= 64 = CryptoFailed CryptoError_ParameterInvalid
    | otherwise = CryptoPassed $ unsafeDoIO $ do
        B.alloc 32 $ \outPtr -> hashInternalMutable passHash saltHash outPtr

hashInternalMutable
    :: (B.ByteArrayAccess pass, B.ByteArrayAccess salt)
    => pass
    -> salt
    -> Ptr Word8
    -> IO ()
hashInternalMutable passHash saltHash outPtr =
    bcryptPbkdfHash passHash saltHash outPtr

finallyErase :: ForeignPtr Word8 -> Int -> IO () -> IO ()
finallyErase fp len action =
    action `E.finally` withForeignPtr fp (\ptr -> memSet ptr 0 len)
