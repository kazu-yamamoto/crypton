-- |
-- Module      : Crypto.Cipher.ChaCha.Poly1305
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : Good
--
-- ChaCha20-Poly1305 (RFC 8439) a message at a time.
--
-- "Crypto.Cipher.ChaChaPoly1305" takes a message in pieces: a state is
-- started, the additional data appended, the body encrypted and the tag
-- taken, each a step of its own.  That is what a protocol wants when the
-- message arrives in pieces, and it is eight foreign calls and the
-- allocations between them when the message was already whole.
--
-- Here the whole message goes in one call.
--
-- The functions are the same shape as "Crypto.Cipher.AES.GCM", so a protocol
-- that offers both ciphers can hold them the same way.
module Crypto.Cipher.ChaCha.Poly1305 (
    Context,
    newContext,
    encrypt,
    decrypt,
    decryptWithTag,
) where

import Crypto.Cipher.Types (AuthTag (..))
import Crypto.Error
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Internal.Imports
import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CUInt (..))
import Foreign.Ptr (Ptr, plusPtr)

-- | A key, checked once.
--
-- ChaCha20-Poly1305 has nothing to precompute from a key: the one-time
-- Poly1305 key comes from the nonce, so it differs for every message.  This
-- holds the thirty-two bytes and the knowledge that they are thirty-two, and
-- exists so that the interface is the one "Crypto.Cipher.AES.GCM" has.
newtype Context = Context B.ScrubbedBytes

instance NFData Context where
    rnf (Context k) = k `seq` ()

-- | Take a key of 32 bytes.  Any other length is reported as
-- 'CryptoError_KeySizeInvalid'.
newContext :: ByteArrayAccess key => key -> CryptoFailable Context
newContext k
    | B.length k /= 32 = CryptoFailed CryptoError_KeySizeInvalid
    | otherwise = CryptoPassed $ Context (B.convert k)
{-# INLINABLE newContext #-}

-- | Encrypt one message.  The result is the ciphertext with the tag after it,
-- which is the shape 'decrypt' expects.
--
-- The nonce is the twelve bytes RFC 8439 defines; any other length gives
-- 'CryptoError_IvSizeInvalid'.  The tag is at most 16 bytes.
{-# INLINABLE encrypt #-}
encrypt
    :: ( ByteArrayAccess nonce
       , ByteArrayAccess aad
       , ByteArrayAccess ba
       , ByteArray output
       )
    => Context
    -> nonce
    -> aad
    -> ba
    -> Int
    -> CryptoFailable output
encrypt (Context k) nonce aad input taglen
    | not (validNonce nonce) = CryptoFailed CryptoError_IvSizeInvalid
    | badTag taglen = CryptoFailed CryptoError_AuthenticationTagSizeInvalid
    | otherwise =
        CryptoPassed $
            unsafeDoIO $
                B.alloc (B.length input + taglen) $ \out ->
                    B.withByteArray k $ \kp ->
                        B.withByteArray nonce $ \np ->
                            B.withByteArray aad $ \ap ->
                                B.withByteArray input $ \ip ->
                                    (callE (B.length input))
                                        out
                                        (out `plusPtr` B.length input)
                                        (fromIntegral taglen)
                                        kp
                                        np
                                        (fromIntegral $ B.length nonce)
                                        ap
                                        (fromIntegral $ B.length aad)
                                        ip
                                        (fromIntegral $ B.length input)

-- | Decrypt one message, in the shape 'encrypt' produced: the ciphertext with
-- its tag after it.  The tag is compared here, every byte of it whatever the
-- answer, and a message whose tag does not match gives 'Nothing' rather than
-- the plaintext.
--
-- 'Nothing' also comes back when the input is shorter than the tag, or the
-- nonce is not twelve bytes.
{-# INLINABLE decrypt #-}
decrypt
    :: (ByteArrayAccess nonce, ByteArrayAccess aad, ByteArray ba)
    => Context
    -> nonce
    -> aad
    -> ba
    -> Int
    -> Maybe ba
decrypt (Context k) nonce aad input taglen
    | not (validNonce nonce) = Nothing
    | badTag taglen || B.length input < taglen = Nothing
    | otherwise = unsafeDoIO $ do
        (r, out) <- B.allocRet bodylen $ \outp ->
            B.withByteArray k $ \kp ->
                B.withByteArray nonce $ \np ->
                    B.withByteArray aad $ \ap ->
                        B.withByteArray body $ \ip ->
                            B.withByteArray tag $ \tp ->
                                (callD bodylen)
                                    outp
                                    tp
                                    (fromIntegral taglen)
                                    kp
                                    np
                                    (fromIntegral $ B.length nonce)
                                    ap
                                    (fromIntegral $ B.length aad)
                                    ip
                                    (fromIntegral bodylen)
        return $ if r /= 0 then Just out else Nothing
  where
    bodylen = B.length input - taglen
    (body, tag) = B.splitAt bodylen input

-- | Decrypt one message, the tag kept apart, and hand back the tag this end
-- computed.
--
-- For a caller whose protocol carries the tag separately from the ciphertext,
-- so that 'decrypt' -- which wants the two together and compares them itself
-- -- does not fit.  Compare the two tags with '=='; the 'Eq' instance of
-- 'AuthTag' is a constant-time comparison, and taking them apart to compare
-- the bytes is how this goes wrong.
--
-- Nothing here says whether the message is authentic.  Until the comparison
-- is made and has come out equal, what this returns is not plaintext, it is
-- what the ciphertext turns into, and a caller must not act on it.
{-# INLINABLE decryptWithTag #-}
decryptWithTag
    :: (ByteArrayAccess nonce, ByteArrayAccess aad, ByteArray ba)
    => Context
    -> nonce
    -> aad
    -> ba
    -> Int
    -> CryptoFailable (ba, AuthTag)
decryptWithTag (Context k) nonce aad input taglen
    | not (validNonce nonce) = CryptoFailed CryptoError_IvSizeInvalid
    | badTag taglen = CryptoFailed CryptoError_AuthenticationTagSizeInvalid
    | otherwise = CryptoPassed $ unsafeDoIO $ do
        (tagbs, out) <- B.allocRet (B.length input) $ \outp ->
            B.alloc taglen $ \tagp ->
                B.withByteArray k $ \kp ->
                    B.withByteArray nonce $ \np ->
                        B.withByteArray aad $ \ap ->
                            B.withByteArray input $ \ip ->
                                (callT (B.length input))
                                    outp
                                    tagp
                                    (fromIntegral taglen)
                                    kp
                                    np
                                    (fromIntegral $ B.length nonce)
                                    ap
                                    (fromIntegral $ B.length aad)
                                    ip
                                    (fromIntegral $ B.length input)
        return (out, AuthTag $ B.convert (tagbs :: B.Bytes))

-- RFC 8439 is the twelve-byte nonce.  ChaCha20 will take eight, but that is
-- the other construction, with a 64-bit block counter, and it is not what
-- this AEAD is defined over -- so it is refused here rather than quietly
-- encrypting under a scheme nobody asked for.
validNonce :: ByteArrayAccess nonce => nonce -> Bool
validNonce n = B.length n == 12

badTag :: Int -> Bool
badTag t = t < 0 || t > 16

-- | An unsafe call keeps a capability for as long as it runs, so it is only
-- for a message short enough that the run is short.  Four kibibytes is what
-- the AES side uses, and it takes in a datagram of any size a network will
-- carry.
shortMessage :: Int
shortMessage = 4096

callE :: Int -> CEncrypt
callE n
    | n <= shortMessage = c_chachapoly_encrypt_unsafe
    | otherwise = c_chachapoly_encrypt

callD :: Int -> CDecrypt
callD n
    | n <= shortMessage = c_chachapoly_decrypt_unsafe
    | otherwise = c_chachapoly_decrypt

callT :: Int -> CEncrypt
callT n
    | n <= shortMessage = c_chachapoly_decrypt_tag_unsafe
    | otherwise = c_chachapoly_decrypt_tag

type CEncrypt =
    Ptr Word8
    -> Ptr Word8
    -> CUInt
    -> Ptr Word8
    -> Ptr Word8
    -> CUInt
    -> Ptr Word8
    -> CUInt
    -> Ptr Word8
    -> CUInt
    -> IO ()

type CDecrypt =
    Ptr Word8
    -> Ptr Word8
    -> CUInt
    -> Ptr Word8
    -> Ptr Word8
    -> CUInt
    -> Ptr Word8
    -> CUInt
    -> Ptr Word8
    -> CUInt
    -> IO CInt

foreign import ccall "crypton_chachapoly.h crypton_chachapoly_encrypt"
    c_chachapoly_encrypt
        :: Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO ()

foreign import ccall unsafe "crypton_chachapoly.h crypton_chachapoly_encrypt"
    c_chachapoly_encrypt_unsafe
        :: Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO ()

foreign import ccall "crypton_chachapoly.h crypton_chachapoly_decrypt"
    c_chachapoly_decrypt
        :: Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO CInt

foreign import ccall unsafe "crypton_chachapoly.h crypton_chachapoly_decrypt"
    c_chachapoly_decrypt_unsafe
        :: Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO CInt

foreign import ccall "crypton_chachapoly.h crypton_chachapoly_decrypt_tag"
    c_chachapoly_decrypt_tag
        :: Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO ()

foreign import ccall unsafe "crypton_chachapoly.h crypton_chachapoly_decrypt_tag"
    c_chachapoly_decrypt_tag_unsafe
        :: Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO ()
