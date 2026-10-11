-- |
-- Module      : Crypto.Random.Entropy.Source
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.Random.Entropy.Source where

import Control.Exception (Exception)
import Data.Word (Word8)
import Foreign.Ptr

-- | The system would not give the entropy it was asked for.
--
-- This is the one failure in the library with nothing to fall back on and
-- nothing sensible to return: a key drawn from bytes that are not random
-- is worse than no key.  It used to be reported with 'error' and 'fail',
-- which left a caller no way to tell it from a bug in the library, and no
-- way to say anything useful about it.
data EntropyError
    = -- | The system offers no source of entropy at all.  On Unix that
      -- means no @getrandom(2)@, no @getentropy(3)@ and no @\/dev@ to read
      -- from; a container built from nothing would look like this.
      NoEntropySource
    | -- | The sources between them gave fewer bytes than were asked for,
      -- three times over.  The two numbers are how many were wanted and
      -- how many arrived.
      EntropyShort Int Int
    | -- | A source that could be opened once could not be opened again.
      -- The string names it.
      EntropySourceLost String
    deriving (Show, Eq)

instance Exception EntropyError

-- | A handle to an entropy maker, either a system capability
-- or a hardware generator.
class EntropySource a where
    -- | Try to open an handle for this source
    entropyOpen :: IO (Maybe a)

    -- | Try to gather a number of entropy bytes into a buffer.
    -- Return the number of actual bytes gathered
    entropyGather :: a -> Ptr Word8 -> Int -> IO Int

    -- | Close an open handle
    entropyClose :: a -> IO ()
