{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.PubKey.Ed25519
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Ed25519 support
module Crypto.PubKey.Ed25519 (
    SecretKey,
    PublicKey,
    Signature,

    -- * Size constants
    publicKeySize,
    secretKeySize,
    signatureSize,

    -- * Smart constructors
    signature,
    publicKey,
    secretKey,

    -- * Methods
    toPublic,
    sign,
    verify,
    generateSecretKey,

    -- * deprecated
    signUnsafe,
) where

import Data.Word
import Foreign.C.Types
import Foreign.Ptr

import Crypto.Error
import Crypto.Internal.ByteArray (
    ByteArrayAccess,
    Bytes,
    ScrubbedBytes,
    withByteArray,
 )
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat
import Crypto.Internal.Imports
import Crypto.Random

-- | An Ed25519 Secret key
newtype SecretKey = SecretKey ScrubbedBytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | An Ed25519 public key
newtype PublicKey = PublicKey Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | An Ed25519 signature
newtype Signature = Signature Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | Try to build a public key from a bytearray
publicKey :: ByteArrayAccess ba => ba -> CryptoFailable PublicKey
publicKey bs
    | B.length bs == publicKeySize =
        CryptoPassed $ PublicKey $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed $ CryptoError_PublicKeySizeInvalid

-- | Try to build a secret key from a bytearray
secretKey :: ByteArrayAccess ba => ba -> CryptoFailable SecretKey
secretKey bs
    | B.length bs == secretKeySize = unsafeDoIO $ withByteArray bs initialize
    | otherwise =
        CryptoFailed CryptoError_SecretKeyStructureInvalid
  where
    initialize inp = do
        valid <- isValidPtr inp
        if valid
            then (CryptoPassed . SecretKey) <$> B.copy bs (\_ -> return ())
            else return $ CryptoFailed CryptoError_SecretKeyStructureInvalid
    isValidPtr _ =
        return True
{-# NOINLINE secretKey #-}

-- | Try to build a signature from a bytearray
signature :: ByteArrayAccess ba => ba -> CryptoFailable Signature
signature bs
    | B.length bs == signatureSize =
        CryptoPassed $ Signature $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed CryptoError_SecretKeyStructureInvalid

-- | Create a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey
    <$> B.allocAndFreeze publicKeySize
    $ \result ->
        withByteArray sec $ \psec ->
            ccrypton_ed25519_publickey psec result
{-# NOINLINE toPublic #-}

-- | Sign a message using the key pair.
--   The public key parameter is ignored and its public key
--   is generated from the secret key parameter to prevent
--   Double Public Key Signing Function Oracle Attack.
sign :: ByteArrayAccess ba => SecretKey -> PublicKey -> ba -> Signature
sign secret _public message =
    Signature $ B.allocAndFreeze signatureSize $ \sig ->
        withByteArray secret $ \sec ->
            withByteArray public $ \pub ->
                withByteArray message $ \msg ->
                    ccrypton_ed25519_sign msg (fromIntegral msgLen) sec pub sig
  where
    !msgLen = B.length message
    public = toPublic secret

-- | Sign a message using the key pair.  This is old 'sing' which may
--   be vulnerable to Double Public Key Signing Function Oracle
--   Attack.
signUnsafe :: ByteArrayAccess ba => SecretKey -> PublicKey -> ba -> Signature
signUnsafe secret public message =
    Signature $ B.allocAndFreeze signatureSize $ \sig ->
        withByteArray secret $ \sec ->
            withByteArray public $ \pub ->
                withByteArray message $ \msg ->
                    ccrypton_ed25519_sign msg (fromIntegral msgLen) sec pub sig
  where
    !msgLen = B.length message
{-# DEPRECATED signUnsafe "Use 'sign' instead" #-}

-- | Verify a message
verify :: ByteArrayAccess ba => PublicKey -> ba -> Signature -> Bool
verify public message signatureVal = unsafeDoIO $
    withByteArray signatureVal $ \sig ->
        withByteArray public $ \pub ->
            withByteArray message $ \msg -> do
                r <- ccrypton_ed25519_sign_open msg (fromIntegral msgLen) pub sig
                return (r == 0)
  where
    !msgLen = B.length message

-- | Generate a secret key
generateSecretKey :: MonadRandom m => m SecretKey
generateSecretKey = SecretKey <$> getRandomBytes secretKeySize

-- | A public key is 32 bytes
publicKeySize :: Int
publicKeySize = 32

-- | A secret key is 32 bytes
secretKeySize :: Int
secretKeySize = 32

-- | A signature is 64 bytes
signatureSize :: Int
signatureSize = 64

foreign import ccall "crypton_ed25519_publickey"
    ccrypton_ed25519_publickey
        :: Ptr SecretKey -- secret key
        -> Ptr PublicKey -- public key
        -> IO ()

foreign import ccall "crypton_ed25519_sign_open"
    ccrypton_ed25519_sign_open
        :: Ptr Word8 -- message
        -> CSize -- message len
        -> Ptr PublicKey -- public
        -> Ptr Signature -- signature
        -> IO CInt

foreign import ccall "crypton_ed25519_sign"
    ccrypton_ed25519_sign
        :: Ptr Word8 -- message
        -> CSize -- message len
        -> Ptr SecretKey -- secret
        -> Ptr PublicKey -- public
        -> Ptr Signature -- signature
        -> IO ()
