-- |
-- Module      : Crypto.Cipher.TripleDES
-- License     : BSD-style
-- Stability   : experimental
-- Portability : ???
module Crypto.Cipher.TripleDES (
    DES_EEE3,
    DES_EDE3,
    DES_EEE2,
    DES_EDE2,
) where

import Crypto.Cipher.DES.Primitive
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B

-- | 3DES with 3 different keys used all in the same direction
data DES_EEE3 = DES_EEE3 Schedule Schedule
    deriving (Eq)

-- | 3DES with 3 different keys used in alternative direction
data DES_EDE3 = DES_EDE3 Schedule Schedule
    deriving (Eq)

-- | 3DES where the first and third keys are equal, used in the same direction
data DES_EEE2 = DES_EEE2 Schedule Schedule
    deriving (Eq)

-- | 3DES where the first and third keys are equal, used in alternative direction
data DES_EDE2 = DES_EDE2 Schedule Schedule
    deriving (Eq)

instance Cipher DES_EEE3 where
    cipherName _ = "3DES_EEE"
    cipherKeySize _ = KeySizeFixed 24
    cipherInit k = init3DES DES_EEE3 Encrypt k

instance Cipher DES_EDE3 where
    cipherName _ = "3DES_EDE"
    cipherKeySize _ = KeySizeFixed 24
    cipherInit k = init3DES DES_EDE3 Decrypt k

instance Cipher DES_EDE2 where
    cipherName _ = "2DES_EDE"
    cipherKeySize _ = KeySizeFixed 16
    cipherInit k = init2DES DES_EDE2 Decrypt k

instance Cipher DES_EEE2 where
    cipherName _ = "2DES_EEE"
    cipherKeySize _ = KeySizeFixed 16
    cipherInit k = init2DES DES_EEE2 Encrypt k

instance BlockCipher DES_EEE3 where
    blockSize _ = 8
    ecbEncrypt (DES_EEE3 enc _) = ecb enc
    ecbDecrypt (DES_EEE3 _ dec) = ecb dec

instance BlockCipher DES_EDE3 where
    blockSize _ = 8
    ecbEncrypt (DES_EDE3 enc _) = ecb enc
    ecbDecrypt (DES_EDE3 _ dec) = ecb dec

instance BlockCipher DES_EEE2 where
    blockSize _ = 8
    ecbEncrypt (DES_EEE2 enc _) = ecb enc
    ecbDecrypt (DES_EEE2 _ dec) = ecb dec

instance BlockCipher DES_EDE2 where
    blockSize _ = 8
    ecbEncrypt (DES_EDE2 enc _) = ecb enc
    ecbDecrypt (DES_EDE2 _ dec) = ecb dec

-- | The schedules of a three stage cipher, for both directions.
--
-- The outer stages encrypt and the middle one goes whichever way the
-- construction says; decrypting is the same three stages in the opposite
-- order, each the other way round.
stages
    :: ByteArrayAccess key
    => Direction
    -- ^ the direction of the middle stage when encrypting
    -> (key, key, key)
    -> (Schedule, Schedule)
stages mid (k1, k2, k3) =
    ( schedule [(Encrypt, k1), (mid, k2), (Encrypt, k3)]
    , schedule [(Decrypt, k3), (opposite mid, k2), (Decrypt, k1)]
    )
  where
    opposite Encrypt = Decrypt
    opposite Decrypt = Encrypt

init3DES
    :: ByteArrayAccess key
    => (Schedule -> Schedule -> a) -> Direction -> key -> CryptoFailable a
init3DES constr mid k
    | B.length k == 24 =
        CryptoPassed $ uncurry constr $ stages mid (part 0, part 8, part 16)
    | otherwise = CryptoFailed CryptoError_KeySizeInvalid
  where
    part = keyPart k

init2DES
    :: ByteArrayAccess key
    => (Schedule -> Schedule -> a) -> Direction -> key -> CryptoFailable a
init2DES constr mid k
    | B.length k == 16 =
        CryptoPassed $ uncurry constr $ stages mid (part 0, part 8, part 0)
    | otherwise = CryptoFailed CryptoError_KeySizeInvalid
  where
    part = keyPart k

-- | The eight bytes of a key that start at the given offset.
keyPart :: ByteArrayAccess key => key -> Int -> ScrubbedBytes
keyPart k i = B.take 8 $ B.drop i (B.convert k :: ScrubbedBytes)
