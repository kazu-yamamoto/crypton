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
-- A ChaCha20 generator per operating system thread, seeded from a
-- process-wide generator, seeded in turn from the system entropy pool with
-- RDRAND mixed in where there is one.  The state and the reseeding live in
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
-- * SHA-512 to combine the system's bytes with RDRAND's, rather than a
--   derivation function a standard would have named.
-- * A mebibyte per thread, and a mebibyte of issued seed for the process
--   generator, as the points at which to reseed.  Those numbers are a
--   choice, not a result.
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
) where

import Data.Word (Word8)
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
