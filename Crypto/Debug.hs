-- |
-- Module      : Crypto.Debug
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- Printing secret key material, on purpose.
--
-- The 'Show' instance of a type that holds a secret does not print it.  That
-- is deliberate: 'Show' is what @print@, a message built with @error@, an
-- exception and a test framework's failure output all reach for, and a
-- private key reaching a log or a bug report that way is an accident nobody
-- asked for.  Those instances render the public part and write @\<secret\>@
-- for the rest.
--
-- This module is how you print one when printing it is what you mean.  What
-- 'debugShow' returns is what the derived 'Show' used to return, so for the
-- types that still have a 'Read' instance
--
-- > read (debugShow k) == k
--
-- and a call site that was serializing a key through @show@ moves by one
-- word.
--
-- Needing 'debugShow' in scope is the record of the intent: nothing here is
-- exported anywhere else, so a search for this module finds every place a key
-- can be revealed.  Do not leave a call to it where production code runs.
module Crypto.Debug (
    DebugShow (..),
    debugShowBytes,
) where

import Data.Bits (shiftR, (.&.))
import qualified Data.ByteArray as BA
import Data.Word (Word8)

-- | Rendering a value with its secret in place.
class DebugShow a where
    -- | Render the value, secret included.
    debugShow :: a -> String

-- | Render a secret that is held as bytes, in hexadecimal.  The secret keys
-- that keep theirs in a @ScrubbedBytes@ never had a 'Show' that printed it,
-- so unlike the rest of this module what comes back is for reading and not
-- for 'Prelude.read'.
debugShowBytes :: BA.ByteArrayAccess ba => String -> ba -> String
debugShowBytes con b = con ++ (' ' : concatMap hex (BA.unpack b))
  where
    hex :: Word8 -> String
    hex w = [digit (w `shiftR` 4), digit (w .&. 0x0f)]
    digit n = "0123456789abcdef" !! fromIntegral n
