-- |
-- Module      : Crypto.Cipher.AES.GCM
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- AES-GCM for callers that send many short messages under one key, which is
-- what a datagram transport does.
--
-- The interface in "Crypto.Cipher.Types" builds a state from the key /and/
-- the nonce and then walks it through appending the additional data,
-- encrypting and finalizing, copying the state at each step.  For a stream
-- that is nothing next to the encryption.  For a QUIC packet it is most of
-- the work: the key schedule and the table of multiples of @H@ depend on the
-- key alone, and rebuilding them for every nonce costs more than encrypting
-- 1440 bytes.
--
-- So here a t'Context' is built from the key once and holds both, and
-- 'encrypt' takes a nonce and a whole message and answers in one call.
--
-- > ctx <- throwCryptoError <$> pure (newContext key)
-- > let packet = encrypt ctx nonce header plaintext 16
--
-- The result is the ciphertext with the tag after it, which is the shape a
-- packet wants.  'decrypt' takes that shape back, compares the tag itself and
-- answers 'Nothing' when it does not match.
--
-- This computes the same thing as the general interface; the tests hold it to
-- that on the same vectors.
module Crypto.Cipher.AES.GCM (
    Context,
    newContext,
    encrypt,
    decrypt,
) where

import Crypto.Cipher.AES.Primitive (
    AES,
    AESGCMKey,
    gcmFullDecrypt,
    gcmFullEncrypt,
    gcmKeyInit,
    initAES,
 )
import Crypto.Error
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B

-- | Everything a key determines: the AES key schedule and the table of
-- multiples of @H@.  Build it once and encrypt as many messages under it as
-- the key is good for.
data Context = Context !AES !AESGCMKey

-- | Take a key of 16, 24 or 32 bytes.  Any other length is reported as
-- 'CryptoError_KeySizeInvalid'.
newContext :: ByteArrayAccess key => key -> CryptoFailable Context
newContext k = do
    aes <- initAES k
    return $ Context aes (gcmKeyInit aes)

-- | Encrypt one message: the nonce, the additional data that is
-- authenticated but not encrypted, the plaintext, and how many bytes of tag
-- to produce, which GCM allows between 4 and 16.
--
-- The answer is the ciphertext followed by the tag.
--
-- A nonce must not be used twice with the same t'Context'.  Twelve bytes is
-- the size GCM is defined for and the only one that does not cost a further
-- pass.
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
    -> output
encrypt (Context aes gk) nonce aad input taglen =
    gcmFullEncrypt aes gk nonce aad input taglen

-- | Decrypt one message, in the shape 'encrypt' produced: the ciphertext with
-- its tag after it.  The tag is compared here, every byte of it whatever the
-- answer, and a message whose tag does not match gives 'Nothing' rather than
-- the plaintext.
--
-- 'Nothing' also comes back when the input is shorter than the tag.
decrypt
    :: (ByteArrayAccess nonce, ByteArrayAccess aad, ByteArray ba)
    => Context
    -> nonce
    -> aad
    -> ba
    -> Int
    -> Maybe ba
decrypt (Context aes gk) nonce aad input taglen
    | taglen < 0 || B.length input < taglen = Nothing
    | otherwise = gcmFullDecrypt aes gk nonce aad body tag
  where
    (body, tag) = B.splitAt (B.length input - taglen) input
