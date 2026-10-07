{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Crypto.Random.Entropy.Unix
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.Random.Entropy.Unix (
    DevRandom,
    DevURandom,
) where

import qualified Control.Exception as E
import Crypto.Random.Entropy.Source
import Data.Word (Word8)
import Foreign.Ptr
import qualified System.IO.Error as E

-- import System.Posix.Types (Fd)
import System.IO

type H = Handle
type DeviceName = String

-- | Entropy device @/dev/random@ on unix system
newtype DevRandom = DevRandom DeviceName

-- | Entropy device @/dev/urandom@ on unix system
newtype DevURandom = DevURandom DeviceName

instance EntropySource DevRandom where
    entropyOpen = fmap DevRandom `fmap` testOpen "/dev/random"
    entropyGather (DevRandom name) ptr n =
        withDev name $ \h -> gatherDevEntropyNonBlock h ptr n
    entropyClose (DevRandom _) = return ()

instance EntropySource DevURandom where
    entropyOpen = fmap DevURandom `fmap` testOpen "/dev/urandom"
    entropyGather (DevURandom name) ptr n =
        withDev name $ \h -> gatherDevEntropy h ptr n
    entropyClose (DevURandom _) = return ()

testOpen :: DeviceName -> IO (Maybe DeviceName)
testOpen filepath = do
    d <- openDev filepath
    case d of
        Nothing -> return Nothing
        Just h -> closeDev h >> return (Just filepath)

openDev :: String -> IO (Maybe H)
openDev filepath =
    (Just `fmap` openAndNoBuffering) `E.catchIOError` \_ -> return Nothing
  where
    openAndNoBuffering = do
        h <- openBinaryFile filepath ReadMode
        hSetBuffering h NoBuffering
        return h

withDev :: String -> (H -> IO a) -> IO a
withDev filepath f =
    openDev filepath >>= \h ->
        case h of
            Nothing -> E.throwIO (EntropySourceLost filepath)
            Just fd -> f fd `E.finally` closeDev fd

closeDev :: H -> IO ()
closeDev h = hClose h `E.catchIOError` \_ -> return ()

gatherDevEntropy :: H -> Ptr Word8 -> Int -> IO Int
gatherDevEntropy h ptr sz =
    (fromIntegral `fmap` hGetBufSome h ptr (fromIntegral sz))
        `E.catchIOError` \_ -> return 0

gatherDevEntropyNonBlock :: H -> Ptr Word8 -> Int -> IO Int
gatherDevEntropyNonBlock h ptr sz =
    (fromIntegral `fmap` hGetBufNonBlocking h ptr (fromIntegral sz))
        `E.catchIOError` \_ -> return 0
