{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE Rank2Types #-}

-- |
-- Module      : Crypto.Cipher.Types.AEAD
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- AEAD cipher basic types
module Crypto.Cipher.Types.AEAD where

import Crypto.Cipher.Types.Base
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Imports

-- | AEAD Implementation
data AEADModeImpl st = AEADModeImpl
    { aeadImplAppendHeader :: forall ba. ByteArrayAccess ba => st -> ba -> st
    -- ^ Adding associated\/additional data to the AEAD context.
    , aeadImplEncrypt :: forall ba. ByteArray ba => st -> ba -> (ba, st)
    -- ^ Encrypiting plaintext and update the AEAD context.
    , aeadImplDecrypt :: forall ba. ByteArray ba => st -> ba -> (ba, st)
    -- ^ Decrypting ciphertext and update the AEAD context.
    , aeadImplFinalize :: st -> Int -> AuthTag
    -- ^ Finalizing the AEAD context and returning the authentication tag.
    }

-- | Algorithm and context for AEAD(Authenticated Encryption with Associated\/Additional Data)
data AEAD cipher = forall st. AEAD
    { aeadModeImpl :: AEADModeImpl st
    , aeadState :: !st
    }

-- | Adding associated\/additional data to the AEAD context.
aeadAppendHeader :: ByteArrayAccess aad => AEAD cipher -> aad -> AEAD cipher
aeadAppendHeader (AEAD impl st) aad = AEAD impl $ aeadImplAppendHeader impl st aad

-- | Encrypting plaintext  and update the AEAD context.
aeadEncrypt :: ByteArray ba => AEAD cipher -> ba -> (ba, AEAD cipher)
aeadEncrypt (AEAD impl st) ba = second (AEAD impl) $ aeadImplEncrypt impl st ba

-- | Decrypting ciphertext and update the AEAD context.
aeadDecrypt :: ByteArray ba => AEAD cipher -> ba -> (ba, AEAD cipher)
aeadDecrypt (AEAD impl st) ba = second (AEAD impl) $ aeadImplDecrypt impl st ba

-- | Finalizing the AEAD context and returning the authentication tag.
aeadFinalize :: AEAD cipher -> Int -> AuthTag
aeadFinalize (AEAD impl st) = aeadImplFinalize impl st

-- | Simple AEAD encryption.
aeadSimpleEncrypt
    :: (ByteArrayAccess aad, ByteArray ba)
    => AEAD a
    -- ^ An AEAD Context
    -> aad
    -- ^ Associated\/additional data
    -> ba
    -- ^ Plaintext
    -> Int
    -- ^ Tag length
    -> (AuthTag, ba)
    -- ^ Authentication tag and ciphertext
aeadSimpleEncrypt aeadIni header input taglen = (tag, output)
  where
    aead = aeadAppendHeader aeadIni header
    (output, aeadFinal) = aeadEncrypt aead input
    tag = aeadFinalize aeadFinal taglen

-- | The shortest authentication tag any mode here produces, four bytes
-- (@CCM_M4@).  Modes that truncate their tag -- GCM and OCB3 -- will
-- compute one of whatever length they are asked for, down to nothing, so
-- 'aeadSimpleDecrypt' refuses a shorter tag than this rather than
-- authenticate fewer bytes than any supported mode ever emits.
minimumTagLength :: Int
minimumTagLength = 4

-- | Simple AEAD decryptio.
--
-- The number of bytes compared is the length of @authTag@.  That is the
-- caller's choice of tag length, so a caller reading a tag off the wire
-- must check its length against the one it expects: passing an
-- attacker-supplied tag straight in lets the attacker pick how much of it
-- is verified.  Tags shorter than 'minimumTagLength' are rejected
-- outright.
aeadSimpleDecrypt
    :: (ByteArrayAccess aad, ByteArray ba)
    => AEAD a
    -- ^ An AEAD Context
    -> aad
    -- ^ Associated\/additional data
    -> ba
    -- ^ Ciphertext
    -> AuthTag
    -- ^ The authentication tag
    -> Maybe ba
    -- ^ Plaintext
aeadSimpleDecrypt aeadIni header input authTag
    | B.length authTag < minimumTagLength = Nothing
    | tag == authTag = Just output
    | otherwise = Nothing
  where
    aead = aeadAppendHeader aeadIni header
    (output, aeadFinal) = aeadDecrypt aead input
    tag = aeadFinalize aeadFinal (B.length authTag)
