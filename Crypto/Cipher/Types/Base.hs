{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.Cipher.Types.Base
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Symmetric cipher basic types
module Crypto.Cipher.Types.Base (
    KeySizeSpecifier (..),
    Cipher (..),
    AuthTag (..),
    AEADMode (..),
    CCM_M (..),
    CCM_L (..),
    DataUnitOffset,
) where

import Crypto.Error
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.DeepSeq
import Data.Word

-- | Different specifier for key size in bytes
data KeySizeSpecifier
    = -- | in the range [min,max]
      KeySizeRange Int Int
    | -- | one of the specified values
      KeySizeEnum [Int]
    | -- | a specific size
      KeySizeFixed Int
    deriving (Show, Eq)

-- | Offset inside an XTS data unit, measured in block size.
type DataUnitOffset = Word32

-- | Authentication Tag for AE cipher mode
newtype AuthTag = AuthTag {unAuthTag :: Bytes}
    deriving (Show, ByteArrayAccess, NFData)

instance Eq AuthTag where
    (AuthTag a) == (AuthTag b) = B.constEq a b

data CCM_M = CCM_M4 | CCM_M6 | CCM_M8 | CCM_M10 | CCM_M12 | CCM_M14 | CCM_M16
    deriving (Show, Eq)
data CCM_L = CCM_L2 | CCM_L3 | CCM_L4 deriving (Show, Eq)

-- | AEAD Mode
data AEADMode
    = -- | OCB3 (RFC 7253) with a 16-byte tag.
      --
      -- The tag length goes into the nonce, so it has to be known before
      -- anything is encrypted; this mode always uses 16 bytes.  Asking
      -- 'Crypto.Cipher.Types.aeadFinalize' for fewer only cuts that tag
      -- short, which is not RFC 7253's shorter tag and does not match other
      -- implementations.  Use 'AEAD_OCB_TAG' for a tag shorter than 16 bytes.
      AEAD_OCB
    | -- | OCB3 (RFC 7253) with the tag length given here, in bytes (1 to 16;
      -- 12 is RFC 7253's TAGLEN of 96 bits).  The length is fixed at
      -- initialisation: the one given to 'Crypto.Cipher.Types.aeadFinalize'
      -- is ignored, and a tag of any other length fails to verify.
      AEAD_OCB_TAG Int
    | AEAD_CCM Int CCM_M CCM_L
    | AEAD_EAX
    | AEAD_CWC
    | AEAD_GCM
    deriving (Show, Eq)

-- | Symmetric cipher class.
class Cipher cipher where
    -- | Initialize a cipher context from a key
    cipherInit :: ByteArray key => key -> CryptoFailable cipher

    -- | Cipher name
    cipherName :: cipher -> String

    -- | return the size of the key required for this cipher.
    -- Some cipher accept any size for key
    cipherKeySize :: cipher -> KeySizeSpecifier
