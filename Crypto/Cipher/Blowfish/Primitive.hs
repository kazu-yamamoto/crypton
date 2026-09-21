-- Rewritten by Vincent Hanquez (c) 2015
--              Lars Petersen (c) 2018
--
-- Original code:
--      Crypto.Cipher.Blowfish.Primitive, copyright (c) 2012 Stijn van Drongelen
--      based on: BlowfishAux.hs (C) 2002 HardCore SoftWare, Doug Hoyte
--           (as found in Crypto-4.2.4)
{-# LANGUAGE BangPatterns #-}

-- |
-- Module      : Crypto.Cipher.Blowfish.Primitive
-- License     : BSD-style
-- Stability   : experimental
-- Portability : Good
--
-- The cipher itself is in C, as is the key setup bcrypt wraps around it:
-- what the schedule costs is the whole of what bcrypt is for, and in Haskell
-- it cost about twice what the usual implementations do.
module Crypto.Cipher.Blowfish.Primitive (
    Context,
    initBlowfish,
    encrypt,
    decrypt,
    bcryptHash,
    bcryptPbkdfHash,
) where

import Crypto.Error
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat
import Crypto.Internal.Imports
import Data.Word (Word32, Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)

-- | The key schedule: the P array and the four S boxes, as the C keeps them.
newtype Context = Context ScrubbedBytes

instance NFData Context where
    rnf a = a `seq` ()

-- | How many bytes of schedule the C wants: eighteen words and four boxes of
-- two hundred and fifty-six.
contextSize :: Int
contextSize = (18 + 4 * 256) * 4

-- | Initialize a new Blowfish context from a key.
--
-- key needs to be between 0 and 448 bits.
initBlowfish :: ByteArrayAccess key => key -> CryptoFailable Context
initBlowfish key
    | B.length key > (448 `div` 8) = CryptoFailed CryptoError_KeySizeInvalid
    | otherwise = CryptoPassed $
        unsafeDoIO $
            fmap Context $
                B.alloc contextSize $ \ctx ->
                    B.withByteArray key $ \k ->
                        c_blowfish_init ctx k (fromIntegral (B.length key))

-- | Encrypt blocks
--
-- Input need to be a multiple of 8 bytes
encrypt :: ByteArray ba => Context -> ba -> ba
encrypt = through c_blowfish_encrypt

-- | Decrypt blocks
--
-- Input need to be a multiple of 8 bytes
decrypt :: ByteArray ba => Context -> ba -> ba
decrypt = through c_blowfish_decrypt

through
    :: ByteArray ba
    => (Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ())
    -> Context
    -> ba
    -> ba
through f (Context ctx) input
    | len `mod` 8 /= 0 =
        error "Crypto.Cipher.Blowfish: input length must be a multiple of 8"
    | otherwise = unsafeDoIO $
        B.alloc len $ \out ->
            B.withByteArray ctx $ \c ->
                B.withByteArray input $ \i -> f c out i (fromIntegral len)
  where
    len = B.length input

-- | What bcrypt does with Blowfish: the key setup that costs what the cost
-- says, and then the sixty-four encryptions.  The answer is 24 bytes, of
-- which bcrypt keeps 23.
--
-- The salt has to be 16 bytes and the key 1 to 73, which is a password of at
-- most 72 with the zero byte the original implementation appends.  'Nothing'
-- means it was given something else.
bcryptHash
    :: (ByteArrayAccess salt, ByteArrayAccess key, ByteArray output)
    => Int
    -- ^ the cost, between 4 and 31
    -> salt
    -> key
    -> Maybe output
bcryptHash cost salt key
    | cost < 4 || cost > 31 = Nothing
    | B.length salt /= 16 = Nothing
    | B.length key < 1 || B.length key > 73 = Nothing
    | otherwise = unsafeDoIO $ do
        (r, out) <- B.allocRet 24 $ \o ->
            B.withByteArray salt $ \s ->
                B.withByteArray key $ \k ->
                    c_bcrypt o (fromIntegral cost) s k (fromIntegral (B.length key))
        return $ if r == 0 then Just out else Nothing

foreign import ccall unsafe "crypton_blowfish_init"
    c_blowfish_init :: Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "crypton_blowfish_encrypt"
    c_blowfish_encrypt :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "crypton_blowfish_decrypt"
    c_blowfish_decrypt :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()

-- the work is what the cost says, so this one may take a while: it is a safe
-- call, which lets the other capabilities carry on while it does
foreign import ccall safe "crypton_bcrypt"
    c_bcrypt :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO CInt

-- | What bcrypt_pbkdf does with Blowfish: the same key setup sixty-four times
-- over, and then the four blocks of its own magic.  Writes 32 bytes where it
-- is pointed, which is what the caller of this one wants.
bcryptPbkdfHash
    :: (ByteArrayAccess pass, ByteArrayAccess salt)
    => pass
    -> salt
    -> Ptr Word8
    -> IO ()
bcryptPbkdfHash pass salt out =
    B.withByteArray pass $ \p ->
        B.withByteArray salt $ \s -> do
            _ <-
                c_bcrypt_pbkdf_hash
                    out
                    p
                    (fromIntegral (B.length pass))
                    s
                    (fromIntegral (B.length salt))
            return ()

foreign import ccall safe "crypton_bcrypt_pbkdf_hash"
    c_bcrypt_pbkdf_hash
        :: Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO CInt
