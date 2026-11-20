{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Random.SysDRG
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : Unix, Windows
--
-- The generator behind the 'Crypto.Random.MonadRandom' instance for 'IO'.
--
-- By default every draw takes a fresh key from the system and keeps
-- nothing ('SystemRandomPerDraw').  What follows describes the faster
-- 'SystemRandomPerThread' mode.
--
-- A ChaCha20 generator per operating system thread, seeded straight from
-- the system entropy pool.
-- The state and the reseeding live in
-- @cbits\/crypton_sysdrg.c@, because a @forkIO@ thread is not an operating
-- system thread -- it moves between capabilities -- so state held against
-- one would be shared by threads running at the same time.
--
-- == What it is, and what it is not
--
-- It is not a DRBG of NIST SP 800-90A.  That standard names three --
-- @Hash_DRBG@, @HMAC_DRBG@ and @CTR_DRBG@ -- and none of them is built on a
-- stream cipher.  The name here is the older and looser sense of the word.
--
-- What it is is the shape @arc4random@ on OpenBSD and @get_random_bytes@ in
-- the Linux kernel both have, and the one asked for in
-- <https://github.com/kazu-yamamoto/crypton/issues/298>.  That shape is
-- common; it is not specified anywhere, so the parts a standard would have
-- fixed were chosen here instead:
--
-- * ChaCha20, rather than AES in counter mode.
-- * SHA-512 over the system's bytes, rather than a derivation function a
--   standard would have named.
-- * A mebibyte per thread as the point at which to reseed.  That number is
--   a choice, not a result.
--
-- The pieces underneath are specified: ChaCha20 is RFC 8439, SHA-512 is
-- FIPS 180-4.  The way they are put together is not.
--
-- == What a compromised state gives away
--
-- Each draw ends by taking the next forty bytes of keystream as the key and
-- nonce and dropping the ones that made the output, so a state read after a
-- draw is not the state that produced it.  ChaCha20 does not run backwards
-- and the key that would be needed is gone, which is backtracking
-- resistance in the terms of SP 800-90A.  Without it, a key stands until
-- the next reseed and anyone holding the state can wind the counter back
-- over everything issued since -- a mebibyte of output that was meant to be
-- secret.  It is what @arc4random@ does, and for the same reason.
--
-- Prediction resistance is what the reseeding gives.  A reseed draws from
-- the system again, so a state that has been read does not determine what
-- comes after one.
module Crypto.Random.SysDRG (
    sysDRGBytes,
    sysDRGReseed,
    SystemRandomMode (..),
    setSystemRandomMode,
    getSystemRandomMode,
) where

import Data.Word (Word32, Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)

import Crypto.Internal.ByteArray (ByteArray)
import qualified Crypto.Internal.ByteArray as B

-- Safe, not unsafe: seeding can reach a getrandom(2) that blocks until the
-- kernel pool is ready, and an unsafe call that blocks holds the capability
-- it runs on.
foreign import ccall safe "crypton_sysdrg_bytes"
    c_sysdrg_bytes :: Ptr Word8 -> CInt -> IO CInt

-- | Draw bytes, or 'Nothing' if the generator cannot be seeded.
--
-- It cannot be seeded where the system has no @getrandom(2)@ or
-- @getentropy(3)@; the caller falls back to
-- 'Crypto.Random.Entropy.getEntropy' there, which is the path this system
-- had before the generator existed.
sysDRGBytes :: ByteArray byteArray => Int -> IO (Maybe byteArray)
sysDRGBytes n = do
    (got, out) <- B.allocRet n $ \ptr ->
        fromIntegral `fmap` c_sysdrg_bytes ptr (fromIntegral n)
    return $ if got == n then Just out else Nothing

-- Unsafe: it only bumps an atomic counter.
foreign import ccall unsafe "crypton_sysdrg_reseed"
    c_sysdrg_reseed :: IO ()

-- | Make every generator reseed before it answers again.  See
-- 'Crypto.Random.reseedSystem'.
sysDRGReseed :: IO ()
sysDRGReseed = c_sysdrg_reseed

-- | Where the bytes behind 'Crypto.Random.MonadRandom' for 'IO' come from.
data SystemRandomMode
    = -- | A fresh key from the system for every draw, expanded with ChaCha20
      -- and dropped.  Nothing is kept between draws, so copies of a process
      -- restored from one saved image -- a virtual machine snapshot, a CRIU
      -- checkpoint -- do not repeat each other's bytes.  The default.
      SystemRandomPerDraw
    | -- | A ChaCha20 generator per operating system thread, reseeded from the
      -- system after a mebibyte, after a fork, after
      -- 'Crypto.Random.reseedSystem', and, unless the interval is 0, once
      -- this many milliseconds of running time have passed since its last
      -- seed (the default is 10) or when realtime has moved a second or
      -- more against the monotonic clock, as a CRIU restore does.  With 0
      -- the clocks are not read at all.  Several times faster
      -- for small draws.  A restored virtual machine snapshot moves neither
      -- clock, so its copies repeat each other until one of these happens.
      SystemRandomPerThread Int
    deriving (Show, Eq)

foreign import ccall unsafe "crypton_sysdrg_set_mode"
    c_sysdrg_set_mode :: CInt -> Word32 -> IO ()

foreign import ccall unsafe "crypton_sysdrg_get_mode"
    c_sysdrg_get_mode :: IO CInt

foreign import ccall unsafe "crypton_sysdrg_get_interval"
    c_sysdrg_get_interval :: IO Word32

-- | Choose the mode for the whole process.  An interval below 0 or above
-- 2^32 - 1 milliseconds is an error.
setSystemRandomMode :: SystemRandomMode -> IO ()
setSystemRandomMode SystemRandomPerDraw = do
    t <- c_sysdrg_get_interval
    c_sysdrg_set_mode 0 t
setSystemRandomMode (SystemRandomPerThread t)
    | t < 0 || toInteger t > toInteger (maxBound :: Word32) =
        error "setSystemRandomMode: reseed interval out of range"
    | otherwise = c_sysdrg_set_mode 1 (fromIntegral t)

-- | The mode in force.
getSystemRandomMode :: IO SystemRandomMode
getSystemRandomMode = do
    m <- c_sysdrg_get_mode
    if m == 1
        then SystemRandomPerThread . fromIntegral <$> c_sysdrg_get_interval
        else return SystemRandomPerDraw
