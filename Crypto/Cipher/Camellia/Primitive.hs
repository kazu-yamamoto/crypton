{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Cipher.Camellia.Primitive
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- Camellia with a 128-bit key, over the C in @cbits/crypton_camellia.c@.
--
-- This only cover Camellia 128 bits for now. The API will change once
-- 192 and 256 mode are implemented too.
module Crypto.Cipher.Camellia.Primitive (
    Camellia,
    initCamellia,
    encrypt,
    decrypt,
) where

import Crypto.Error
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat (unsafeDoIO)
import Data.Word
import Foreign.Ptr (Ptr)

-- | The subkeys of RFC 3713 section 2.2: kw, k and ke, as 26 64-bit words.
newtype Camellia = Camellia Bytes
    deriving (Eq)

scheduleSize :: Int
scheduleSize = 26 * 8

blockBytes :: Int
blockBytes = 16

-- | Initialize a 128-bit key.
initCamellia :: ByteArrayAccess key => key -> CryptoFailable Camellia
initCamellia key
    | B.length key /= 16 = CryptoFailed CryptoError_KeySizeInvalid
    | otherwise =
        CryptoPassed $
            Camellia $
                B.allocAndFreeze scheduleSize $ \ks ->
                    B.withByteArray key $ \k -> c_camellia_init ks k

-- | Encrypt the given input, which has to be a whole number of blocks.
encrypt :: ByteArray ba => Camellia -> ba -> ba
encrypt = run c_camellia_encrypt

-- | Decrypt the given input, which has to be a whole number of blocks.
decrypt :: ByteArray ba => Camellia -> ba -> ba
decrypt = run c_camellia_decrypt

run
    :: ByteArray ba
    => (Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ())
    -> Camellia
    -> ba
    -> ba
run f (Camellia sched) input
    | len `mod` blockBytes /= 0 =
        error $
            "Crypto.Cipher.Camellia: input length must be a multiple of block size (16). Its length is: "
                ++ show len
    | otherwise = unsafeDoIO $
        B.alloc len $ \out ->
            B.withByteArray sched $ \ks ->
                B.withByteArray input $ \inp ->
                    f out ks inp (fromIntegral (len `div` blockBytes))
  where
    len = B.length input

foreign import ccall unsafe "crypton_camellia.h crypton_camellia_init"
    c_camellia_init :: Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "crypton_camellia.h crypton_camellia_encrypt"
    c_camellia_encrypt :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "crypton_camellia.h crypton_camellia_decrypt"
    c_camellia_decrypt :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()
