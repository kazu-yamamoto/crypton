{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.Internal.Poly1305
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- The Poly1305 key with its constructor, for the modules here that build one
-- from bytes whose length they already know.  "Crypto.MAC.Poly1305" exports
-- the type without the constructor, so that outside this library a key can
-- only be made by 'key', which checks.
module Crypto.Internal.Poly1305 (
    Key (..),
    key,
) where

import Crypto.Error
import Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.DeepSeq

-- | A Poly1305 key: thirty-two bytes, and the length is checked here rather
-- than at every use.  'Crypto.MAC.Poly1305.initialize' and
-- 'Crypto.MAC.Poly1305.auth' take one of these and cannot fail, so a caller
-- that holds a key does not carry an error case for a length it already knows
-- is right.
newtype Key = Key ScrubbedBytes
    deriving (ByteArrayAccess, Eq, NFData)

-- | Take thirty-two bytes for a key.  A different length is reported as
-- 'CryptoError_MacKeyInvalid'; nothing else about a key can be wrong.
key :: ByteArrayAccess ba => ba -> CryptoFailable Key
key k
    | B.length k /= 32 = CryptoFailed CryptoError_MacKeyInvalid
    | otherwise = CryptoPassed $ Key $ B.convert k
