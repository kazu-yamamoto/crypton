-- |
-- Module      : Crypto.PubKey.RSA.OAEP
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- RSA OAEP mode
-- <http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>
module Crypto.PubKey.RSA.OAEP (
    OAEPParams (..),
    defaultOAEPParams,

    -- * OAEP encryption
    encryptWithSeed,
    encrypt,

    -- * OAEP decryption
    decrypt,
    decryptSafer,
) where

import Crypto.Hash
import Crypto.PubKey.Internal (and')
import Crypto.PubKey.MaskGenFunction
import Crypto.PubKey.RSA (generateBlinder)
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types
import Crypto.Random.Types
import Data.Bits (complement, shiftR, xor, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.List (foldl')
import Data.Word (Word32)
import Prelude hiding (foldl')

import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B (constEq, convert)

-- | Parameters for OAEP encryption/decryption
data OAEPParams hash seed output = OAEPParams
    { oaepHash :: hash
    -- ^ Hash function to use.
    , oaepMaskGenAlg :: MaskGenAlgorithm seed output
    -- ^ Mask Gen algorithm to use.
    , oaepLabel :: Maybe ByteString
    -- ^ Optional label prepended to message.
    }

-- | Default Params with a specified hash function
defaultOAEPParams
    :: (ByteArrayAccess seed, ByteArray output, HashAlgorithm hash)
    => hash
    -> OAEPParams hash seed output
defaultOAEPParams hashAlg =
    OAEPParams
        { oaepHash = hashAlg
        , oaepMaskGenAlg = mgf1 hashAlg
        , oaepLabel = Nothing
        }

-- | Encrypt a message using OAEP with a predefined seed.
encryptWithSeed
    :: HashAlgorithm hash
    => ByteString
    -- ^ Seed
    -> OAEPParams hash ByteString ByteString
    -- ^ OAEP params to use for encryption
    -> PublicKey
    -- ^ Public key.
    -> ByteString
    -- ^ Message to encrypt
    -> Either Error ByteString
encryptWithSeed seed oaep pk msg
    | k < 2 * hashLen + 2 = Left InvalidParameters
    | B.length seed /= hashLen = Left InvalidParameters
    | mLen > k - 2 * hashLen - 2 = Left MessageTooLong
    | otherwise = Right $ ep pk em
  where
    -- parameters
    k = public_size pk
    mLen = B.length msg
    mgf = oaepMaskGenAlg oaep
    labelHash = hashWith (oaepHash oaep) (maybe B.empty id $ oaepLabel oaep)
    hashLen = hashDigestSize (oaepHash oaep)

    -- put fields
    ps = B.replicate (k - mLen - 2 * hashLen - 2) 0
    db = B.concat [B.convert labelHash, ps, B.singleton 0x1, msg]
    dbmask = mgf seed (k - hashLen - 1)
    maskedDB = B.pack $ B.zipWith xor db dbmask
    seedMask = mgf maskedDB hashLen
    maskedSeed = B.pack $ B.zipWith xor seed seedMask
    em = B.concat [B.singleton 0x0, maskedSeed, maskedDB]

-- | Encrypt a message using OAEP
encrypt
    :: (HashAlgorithm hash, MonadRandom m)
    => OAEPParams hash ByteString ByteString
    -- ^ OAEP params to use for encryption.
    -> PublicKey
    -- ^ Public key.
    -> ByteString
    -- ^ Message to encrypt
    -> m (Either Error ByteString)
encrypt oaep pk msg = do
    seed <- getRandomBytes hashLen
    return (encryptWithSeed seed oaep pk msg)
  where
    hashLen = hashDigestSize (oaepHash oaep)

-- | un-pad a OAEP encoded message.
--
-- It doesn't apply the RSA decryption primitive
--
-- The data block is scanned in full rather than up to the 01 octet separating
-- the padding from the message, and the label hash and the leading octet are
-- compared without an early exit, so neither the length of the padding nor
-- where a comparison first differs shows up in how long this takes.
--
-- What remains visible is the result itself: whether the block was well formed,
-- and the length of the message when it was.  That is the signal Manger's
-- attack needs, so a caller that decrypts attacker-supplied ciphertext must not
-- pass the distinction on.
unpad
    :: HashAlgorithm hash
    => OAEPParams hash ByteString ByteString
    -- ^ OAEP params to use
    -> Int
    -- ^ size of the key in bytes
    -> ByteString
    -- ^ encoded message (not encrypted)
    -> Either Error ByteString
unpad oaep k em
    | paddingSuccess = Right msg
    | otherwise = Left MessageNotRecognized
  where
    -- parameters
    mgf = oaepMaskGenAlg oaep
    labelHash =
        B.convert $ hashWith (oaepHash oaep) (maybe B.empty id $ oaepLabel oaep)
            :: ByteString
    hashLen = hashDigestSize (oaepHash oaep)
    -- getting em's fields
    (pb, em0) = B.splitAt 1 em
    (maskedSeed, maskedDB) = B.splitAt hashLen em0
    seedMask = mgf maskedDB hashLen
    seed = B.pack $ B.zipWith xor maskedSeed seedMask
    dbmask = mgf seed (k - hashLen - 1)
    db = B.pack $ B.zipWith xor maskedDB dbmask
    -- getting db's fields
    (labelHash', db1) = B.splitAt hashLen db

    -- index of the first nonzero octet in db1, or its length when every octet
    -- is zero; all of them are looked at either way
    oneIndex =
        fst $
            foldl'
                step
                (fromIntegral (B.length db1) :: Word32, 1 :: Word32)
                (zip [0 ..] (B.unpack db1))
    step (idx, unseen) (i, b) = (select found i idx, unseen .&. complement found)
      where
        w = fromIntegral b :: Word32
        -- 0 when b is zero, 1 otherwise
        nonZero = (w .|. negate w) `shiftR` 31
        -- all ones at the first nonzero octet only
        found = negate (unseen .&. nonZero)
    select mask a b = (a .&. mask) .|. (b .&. complement mask)

    ps1 = B.take 1 $ B.drop (fromIntegral oneIndex) db1
    msg = B.drop (fromIntegral oneIndex + 1) db1

    paddingSuccess =
        and'
            [ labelHash' `B.constEq` labelHash
            , ps1 `B.constEq` B.replicate 1 0x1
            , pb `B.constEq` B.replicate 1 0x0
            ]

-- | Decrypt a ciphertext using OAEP
--
-- When the signature is not in a context where an attacker could gain
-- information from the timing of the operation, the blinder can be set to None.
--
-- If unsure always set a blinder or use decryptSafer
decrypt
    :: HashAlgorithm hash
    => Maybe Blinder
    -- ^ Optional blinder
    -> OAEPParams hash ByteString ByteString
    -- ^ OAEP params to use for decryption
    -> PrivateKey
    -- ^ Private key
    -> ByteString
    -- ^ Cipher text
    -> Either Error ByteString
decrypt blinder oaep pk cipher
    | B.length cipher /= k = Left MessageSizeIncorrect
    | k < 2 * hashLen + 2 = Left InvalidParameters
    | otherwise = unpad oaep (private_size pk) $ dp blinder pk cipher
  where
    -- parameters
    k = private_size pk
    hashLen = hashDigestSize (oaepHash oaep)

-- | Decrypt a ciphertext using OAEP and by automatically generating a blinder.
decryptSafer
    :: (HashAlgorithm hash, MonadRandom m)
    => OAEPParams hash ByteString ByteString
    -- ^ OAEP params to use for decryption
    -> PrivateKey
    -- ^ Private key
    -> ByteString
    -- ^ Cipher text
    -> m (Either Error ByteString)
decryptSafer oaep pk cipher = do
    blinder <- generateBlinder (private_n pk)
    return (decrypt (Just blinder) oaep pk cipher)
