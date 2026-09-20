-- |
-- Module      : Crypto.Cipher.Types.Utils
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Basic utility for cipher related stuff
module Crypto.Cipher.Types.Utils where

import Crypto.Internal.ByteArray (ByteArray)
import qualified Crypto.Internal.ByteArray as B
import Data.ByteString (ByteString)
import qualified Data.ByteString as S

-- | Chunk some input byte array into @sz byte list of byte array.
--
-- The input is held as a 'ByteString' while it is cut up, because
-- 'Crypto.Internal.ByteArray.splitAt' copies both halves whatever the type
-- underneath: cutting a block off the front that way copies the rest of the
-- message, once per block, and so the message about n/2 times.  A ByteString
-- shares instead, and only the blocks themselves are copied out.
chunk :: ByteArray b => Int -> b -> [b]
chunk sz bs = map B.convert (split (B.convert bs :: ByteString))
  where
    split b
        | S.length b <= sz = [b]
        | otherwise = let (b1, b2) = S.splitAt sz b in b1 : split b2
