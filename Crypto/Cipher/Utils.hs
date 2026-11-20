-- |
-- Module      : Crypto.Cipher.Utils
-- License     : BSD-style
-- Stability   : experimental
-- Portability : good
--
-- Helpers for writing 'Cipher' instances.
module Crypto.Cipher.Utils (
    validateKeySize,
) where

import Crypto.Cipher.Types
import Crypto.Error

import Data.ByteArray as BA

-- | Pass the key on if its length is one 'cipherKeySize' allows, and report
-- 'CryptoError_KeySizeInvalid' otherwise.  The cipher argument only names
-- the type; it is not evaluated.
validateKeySize
    :: (ByteArrayAccess key, Cipher cipher) => cipher -> key -> CryptoFailable key
validateKeySize c k =
    if validKeyLength
        then CryptoPassed k
        else CryptoFailed CryptoError_KeySizeInvalid
  where
    keyLength = BA.length k
    validKeyLength = case cipherKeySize c of
        KeySizeRange low high -> keyLength >= low && keyLength <= high
        KeySizeEnum lengths -> keyLength `elem` lengths
        KeySizeFixed s -> keyLength == s
