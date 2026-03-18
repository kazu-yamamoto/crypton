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
    hashInternal,
)
where

import Control.Exception (finally)
import Control.Monad (when)
import qualified Crypto.Cipher.Blowfish.Box as Blowfish
import qualified Crypto.Cipher.Blowfish.Primitive as Blowfish
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
generate
    :: (B.ByteArray pass, B.ByteArray salt, B.ByteArray output)
    => Parameters
    -> pass
    -> salt
    -> output
generate params pass salt
    | iterCounts params < 1 = error "BCryptPBKDF: iterCounts must be > 0"
    | keyLen < 1 || keyLen > 1024 =
        error "BCryptPBKDF: outputLength must be in 1..1024"
    | otherwise = B.unsafeCreate keyLen deriveKey
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
        ksClean <- Blowfish.createKeySchedule
        ksDirty <- Blowfish.createKeySchedule
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
                                                    Blowfish.copyKeySchedule ksDirty ksClean
                                                    hashInternalMutable ksDirty passHashBS saltHashBS tmpPtr
                                                    memCopy outPtr tmpPtr outLen
                                                    -- Remaining rounds.
                                                    forM_ [2 .. iterCounts params] $ const $ do
                                                        hashInternalInit shaPtr
                                                        hashInternalUpdate shaPtr tmpPtr (fromIntegral tmpLen)
                                                        hashInternalFinalize shaPtr (castPtr saltHashPtr)
                                                        let saltHashBS2 = BSI.fromForeignPtr saltHashFP 0 hashLen
                                                        Blowfish.copyKeySchedule ksDirty ksClean
                                                        hashInternalMutable ksDirty passHashBS saltHashBS2 tmpPtr
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
hashInternal
    :: (B.ByteArrayAccess pass, B.ByteArrayAccess salt, B.ByteArray output)
    => pass
    -> salt
    -> output
hashInternal passHash saltHash
    | B.length passHash /= 64 = error "passHash must be 512 bits"
    | B.length saltHash /= 64 = error "saltHash must be 512 bits"
    | otherwise = unsafeDoIO $ do
        ks0 <- Blowfish.createKeySchedule
        B.alloc 32 $ \outPtr -> hashInternalMutable ks0 passHash saltHash outPtr

hashInternalMutable
    :: (B.ByteArrayAccess pass, B.ByteArrayAccess salt)
    => Blowfish.KeySchedule
    -> pass
    -> salt
    -> Ptr Word8
    -> IO ()
hashInternalMutable bfks passHash saltHash outPtr = do
    Blowfish.expandKeyWithSalt bfks passHash saltHash
    forM_ [0 .. 63 :: Int] $ const $ do
        Blowfish.expandKey bfks saltHash
        Blowfish.expandKey bfks passHash
    -- "OxychromaticBlowfishSwatDynamite" represented as 4 Word64 in big-endian.
    store 0 =<< cipher 64 0x4f78796368726f6d
    store 8 =<< cipher 64 0x61746963426c6f77
    store 16 =<< cipher 64 0x6669736853776174
    store 24 =<< cipher 64 0x44796e616d697465
  where
    store :: Int -> Word64 -> IO ()
    store o w64 = do
        pokeByteOff outPtr (o + 0) (fromIntegral (w64 `shiftR` 32) :: Word8)
        pokeByteOff outPtr (o + 1) (fromIntegral (w64 `shiftR` 40) :: Word8)
        pokeByteOff outPtr (o + 2) (fromIntegral (w64 `shiftR` 48) :: Word8)
        pokeByteOff outPtr (o + 3) (fromIntegral (w64 `shiftR` 56) :: Word8)
        pokeByteOff outPtr (o + 4) (fromIntegral (w64 `shiftR` 0) :: Word8)
        pokeByteOff outPtr (o + 5) (fromIntegral (w64 `shiftR` 8) :: Word8)
        pokeByteOff outPtr (o + 6) (fromIntegral (w64 `shiftR` 16) :: Word8)
        pokeByteOff outPtr (o + 7) (fromIntegral (w64 `shiftR` 24) :: Word8)
    cipher :: Int -> Word64 -> IO Word64
    cipher 0 block = return block
    cipher i block = Blowfish.cipherBlockMutable bfks block >>= cipher (i - 1)

finallyErase :: ForeignPtr Word8 -> Int -> IO () -> IO ()
finallyErase fp len action =
    action `finally` withForeignPtr fp (\ptr -> memSet ptr 0 len)
