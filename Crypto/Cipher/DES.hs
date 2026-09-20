-- |
-- Module      : Crypto.Cipher.DES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
-- DES, which is here because callers still meet it rather than because it
-- should be chosen: its 56-bit key is exhaustible.  Prefer "Crypto.Cipher.AES".
module Crypto.Cipher.DES (
    DES,
) where

import Crypto.Cipher.DES.Primitive
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Internal.ByteArray (ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B

-- | DES Context
data DES = DES Schedule Schedule
    deriving (Eq)

instance Cipher DES where
    cipherName _ = "DES"
    cipherKeySize _ = KeySizeFixed 8
    cipherInit k = initDES k

instance BlockCipher DES where
    blockSize _ = 8
    ecbEncrypt (DES enc _) = ecb enc
    ecbDecrypt (DES _ dec) = ecb dec

initDES :: ByteArrayAccess key => key -> CryptoFailable DES
initDES k
    | B.length k == 8 =
        CryptoPassed $ DES (schedule [(Encrypt, k)]) (schedule [(Decrypt, k)])
    | otherwise = CryptoFailed CryptoError_KeySizeInvalid
