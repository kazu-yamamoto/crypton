{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.KDF.PBKDF2
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Password Based Key Derivation Function 2
module Crypto.KDF.PBKDF2 (
    PRF,
    prfHMAC,
    Parameters (..),
    generate,
    tryGenerate,
    fastPBKDF2_SHA1,
    tryFastPBKDF2_SHA1,
    fastPBKDF2_SHA256,
    tryFastPBKDF2_SHA256,
    fastPBKDF2_SHA512,
    tryFastPBKDF2_SHA512,
) where

import Data.Bits
import Data.Word
import Foreign.C.Types (CSize (..), CUInt (..))
import Foreign.Marshal.Alloc
import Foreign.Ptr (Ptr, plusPtr)

import Crypto.Error
import Crypto.Hash (HashAlgorithm)
import qualified Crypto.MAC.HMAC as HMAC

import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import Data.Memory.PtrMethods

-- | The PRF used for PBKDF2
type PRF password =
    password
    -- ^ the password parameters
    -> Bytes
    -- ^ the content
    -> Bytes
    -- ^ prf(password,content)

-- | PRF for PBKDF2 using HMAC with the hash algorithm as parameter
prfHMAC
    :: (HashAlgorithm a, ByteArrayAccess password)
    => a
    -> PRF password
prfHMAC alg k = hmacIncr alg (HMAC.initialize k)
  where
    hmacIncr :: HashAlgorithm a => a -> HMAC.Context a -> (Bytes -> Bytes)
    hmacIncr _ !ctx = \b -> B.convert $ HMAC.finalize $ HMAC.update ctx b

-- | Parameters for PBKDF2
data Parameters = Parameters
    { iterCounts :: Int
    -- ^ the number of user-defined iterations for the algorithms. e.g. WPA2 uses 4000.
    --   (must be > 0)
    , outputLength :: Int
    -- ^ the number of bytes to generate out of PBKDF2
    --   (must not be negative)
    }

-- | Report parameters no PBKDF2 entry point accepts.
--
-- An iteration count below one derives a key that is not a key at all, and a
-- negative output length asks for a buffer that cannot be allocated.
validateParameters :: Parameters -> Maybe CryptoError
validateParameters params
    | iterCounts params < 1 = Just CryptoError_ParameterInvalid
    | outputLength params < 0 = Just CryptoError_ParameterInvalid
    | otherwise = Nothing

-- | generate the pbkdf2 key derivation function from the output
--
-- Parameters outside the ranges documented for 'Parameters' raise
-- 'CryptoError_ParameterInvalid'; 'tryGenerate' reports the same condition as
-- 'CryptoFailed'.
generate
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray ba)
    => PRF password
    -> Parameters
    -> password
    -> salt
    -> ba
generate prf params password salt =
    throwCryptoError (tryGenerate prf params password salt)

-- | generate the pbkdf2 key derivation function from the output, reporting
-- parameters the implementation refuses rather than raising.
tryGenerate
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray ba)
    => PRF password
    -> Parameters
    -> password
    -> salt
    -> CryptoFailable ba
tryGenerate prf params password salt
    | Just err <- validateParameters params = CryptoFailed err
    | otherwise = CryptoPassed $ B.allocAndFreeze (outputLength params) $ \p -> do
        memSet p 0 (outputLength params)
        loop 1 (outputLength params) p
  where
    !runPRF = prf password
    !hLen = B.length $ runPRF B.empty

    -- run the following f function on each complete chunk.
    -- when having an incomplete chunk, we call partial.
    -- partial need to be the last call.
    --
    -- f(pass,salt,c,i) = U1 xor U2 xor .. xor Uc
    -- U1 = PRF(pass,salt || BE32(i))
    -- Uc = PRF(pass,Uc-1)
    loop iterNb len p
        | len == 0 = return ()
        | len < hLen = partial iterNb len p
        | otherwise = do
            let applyMany 0 _ = return ()
                applyMany i uprev = do
                    let uData = runPRF uprev
                    B.withByteArray uData $ \u -> memXor p p u hLen
                    applyMany (i - 1) uData
            applyMany (iterCounts params) (B.convert salt `B.append` toBS iterNb)
            loop (iterNb + 1) (len - hLen) (p `plusPtr` hLen)

    partial iterNb len p = allocaBytesAligned hLen 8 $ \tmp -> do
        let applyMany :: Int -> Bytes -> IO ()
            applyMany 0 _ = return ()
            applyMany i uprev = do
                let uData = runPRF uprev
                B.withByteArray uData $ \u -> memXor tmp tmp u hLen
                applyMany (i - 1) uData
        memSet tmp 0 hLen
        applyMany (iterCounts params) (B.convert salt `B.append` toBS iterNb)
        memCopy p tmp len

    -- big endian encoding of Word32
    toBS :: ByteArray ba => Word32 -> ba
    toBS w = B.pack [a, b, c, d]
      where
        a = fromIntegral (w `shiftR` 24)
        b = fromIntegral ((w `shiftR` 16) .&. 0xff)
        c = fromIntegral ((w `shiftR` 8) .&. 0xff)
        d = fromIntegral (w .&. 0xff)
{-# NOINLINE tryGenerate #-}

-- | PBKDF2 with HMAC-SHA1, using the bundled C implementation.
--
-- Parameters outside the ranges documented for 'Parameters' raise
-- 'CryptoError_ParameterInvalid'; 'tryFastPBKDF2_SHA1' reports the same condition
-- as 'CryptoFailed'.
fastPBKDF2_SHA1
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray out)
    => Parameters
    -> password
    -> salt
    -> out
fastPBKDF2_SHA1 params password salt =
    throwCryptoError (tryFastPBKDF2_SHA1 params password salt)

-- | PBKDF2 with HMAC-SHA1, reporting parameters the implementation refuses
-- rather than raising.
tryFastPBKDF2_SHA1
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray out)
    => Parameters
    -> password
    -> salt
    -> CryptoFailable out
tryFastPBKDF2_SHA1 params password salt
    | Just err <- validateParameters params = CryptoFailed err
    | otherwise = CryptoPassed $ B.allocAndFreeze (outputLength params) $ \outPtr ->
        B.withByteArray password $ \passPtr ->
            B.withByteArray salt $ \saltPtr ->
                c_crypton_fastpbkdf2_hmac_sha1
                    passPtr
                    (fromIntegral $ B.length password)
                    saltPtr
                    (fromIntegral $ B.length salt)
                    (fromIntegral $ iterCounts params)
                    outPtr
                    (fromIntegral $ outputLength params)

-- | PBKDF2 with HMAC-SHA256, using the bundled C implementation.
--
-- Parameters outside the ranges documented for 'Parameters' raise
-- 'CryptoError_ParameterInvalid'; 'tryFastPBKDF2_SHA256' reports the same condition
-- as 'CryptoFailed'.
fastPBKDF2_SHA256
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray out)
    => Parameters
    -> password
    -> salt
    -> out
fastPBKDF2_SHA256 params password salt =
    throwCryptoError (tryFastPBKDF2_SHA256 params password salt)

-- | PBKDF2 with HMAC-SHA256, reporting parameters the implementation refuses
-- rather than raising.
tryFastPBKDF2_SHA256
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray out)
    => Parameters
    -> password
    -> salt
    -> CryptoFailable out
tryFastPBKDF2_SHA256 params password salt
    | Just err <- validateParameters params = CryptoFailed err
    | otherwise = CryptoPassed $ B.allocAndFreeze (outputLength params) $ \outPtr ->
        B.withByteArray password $ \passPtr ->
            B.withByteArray salt $ \saltPtr ->
                c_crypton_fastpbkdf2_hmac_sha256
                    passPtr
                    (fromIntegral $ B.length password)
                    saltPtr
                    (fromIntegral $ B.length salt)
                    (fromIntegral $ iterCounts params)
                    outPtr
                    (fromIntegral $ outputLength params)

-- | PBKDF2 with HMAC-SHA512, using the bundled C implementation.
--
-- Parameters outside the ranges documented for 'Parameters' raise
-- 'CryptoError_ParameterInvalid'; 'tryFastPBKDF2_SHA512' reports the same condition
-- as 'CryptoFailed'.
fastPBKDF2_SHA512
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray out)
    => Parameters
    -> password
    -> salt
    -> out
fastPBKDF2_SHA512 params password salt =
    throwCryptoError (tryFastPBKDF2_SHA512 params password salt)

-- | PBKDF2 with HMAC-SHA512, reporting parameters the implementation refuses
-- rather than raising.
tryFastPBKDF2_SHA512
    :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray out)
    => Parameters
    -> password
    -> salt
    -> CryptoFailable out
tryFastPBKDF2_SHA512 params password salt
    | Just err <- validateParameters params = CryptoFailed err
    | otherwise = CryptoPassed $ B.allocAndFreeze (outputLength params) $ \outPtr ->
        B.withByteArray password $ \passPtr ->
            B.withByteArray salt $ \saltPtr ->
                c_crypton_fastpbkdf2_hmac_sha512
                    passPtr
                    (fromIntegral $ B.length password)
                    saltPtr
                    (fromIntegral $ B.length salt)
                    (fromIntegral $ iterCounts params)
                    outPtr
                    (fromIntegral $ outputLength params)

foreign import ccall unsafe "crypton_pbkdf2.h crypton_fastpbkdf2_hmac_sha1"
    c_crypton_fastpbkdf2_hmac_sha1
        :: Ptr Word8
        -> CSize
        -> Ptr Word8
        -> CSize
        -> CUInt
        -> Ptr Word8
        -> CSize
        -> IO ()

foreign import ccall unsafe "crypton_pbkdf2.h crypton_fastpbkdf2_hmac_sha256"
    c_crypton_fastpbkdf2_hmac_sha256
        :: Ptr Word8
        -> CSize
        -> Ptr Word8
        -> CSize
        -> CUInt
        -> Ptr Word8
        -> CSize
        -> IO ()

foreign import ccall unsafe "crypton_pbkdf2.h crypton_fastpbkdf2_hmac_sha512"
    c_crypton_fastpbkdf2_hmac_sha512
        :: Ptr Word8
        -> CSize
        -> Ptr Word8
        -> CSize
        -> CUInt
        -> Ptr Word8
        -> CSize
        -> IO ()
