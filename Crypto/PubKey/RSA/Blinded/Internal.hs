{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-cse -fno-full-laziness #-}

-- |
-- Module      : Crypto.PubKey.RSA.Blinded.Internal
-- License     : BSD-style
-- Stability   : experimental
-- Portability : Good
--
-- A private key with a blinding pair that is reused by squaring, as OpenSSL
-- does, rather than generated afresh for every operation.  The key is a value
-- threaded through the operations, as a hash 'Crypto.Hash.Context' is.
module Crypto.PubKey.RSA.Blinded.Internal (
    BlindedKey (..),
    blindedKey,
    dpBlinded,
    Draw,
    drawFor,
    withBlindingFor,
    dpWithPair,
) where

import Data.IORef
import System.IO.Unsafe (unsafePerformIO)

import Crypto.Internal.ByteArray (ByteArray, ScrubbedBytes)
import Crypto.Number.Generate (generateMax)
import Crypto.Number.ModArithmetic (expFast, inverseCoprimes)
import Crypto.Number.Serialize (i2ospOf_, os2ip)
import Crypto.PubKey.RSA.Prim (dp)
import Crypto.PubKey.RSA.Types
import Crypto.Random.Types

-- | A private key together with the blinding its next operation uses.
--
-- Each operation multiplies the input by @r^e@ and the output by @r^-1@, and
-- returns the key with both squared for the next one, so a pair costs two
-- multiplications after the first.  A new @r@ is drawn every 32 operations.
-- Use the key an operation returns: handing the same one to two operations
-- gives both the same pair.
data BlindedKey = BlindedKey
    { blindedPrivateKey :: PrivateKey
    -- ^ the key it was made from
    , blindedPair :: Pair
    }

-- | @r^e@ and @r^-1@ modulo n, and how many more uses they have after this.
data Pair = Pair !Int !Integer !Integer | Spent

-- | Uses of one @r@ before another is drawn, OpenSSL's number.
refresh :: Int
refresh = 32

-- | A t'BlindedKey' for a private key.  The first pair is drawn when it is
-- first used.
blindedKey :: PrivateKey -> BlindedKey
blindedKey pk = BlindedKey pk Spent

-- | The random numbers a new pair is made from: drawing them is cheap, and
-- making the pair, an inverse and an exponentiation, is done only if needed.
data Draw = Draw !Integer !Integer

-- | Draw for a key, as 'Crypto.PubKey.RSA.generateBlinder' does.
drawFor :: forall m. MonadRandom m => PrivateKey -> m Draw
drawFor pk = do
    r <- generateMax (private_n pk)
    u <- os2ip <$> (getRandomBytes 16 :: m ScrubbedBytes)
    return (Draw r u)

-- | @r^e@ and @r^-1@.  The inverse is taken of @r*u@ and multiplied by @u@,
-- so the extended Euclidean algorithm never sees @r@, as in
-- 'Crypto.PubKey.RSA.generateBlinder'.
makePair :: PrivateKey -> Draw -> (Integer, Integer)
makePair pk (Draw r u) =
    (expFast r (private_e pk) n, (inverseCoprimes ((r * u) `mod` n) n * u) `mod` n)
  where
    n = private_n pk

-- | The pair for this operation, and the key holding the next one.  The
-- draw is used only when a new pair is due.
takePair :: Draw -> BlindedKey -> ((Integer, Integer), BlindedKey)
takePair d (BlindedKey pk pair) = case pair of
    Pair k a ai -> ((a, ai), BlindedKey pk (next k a ai))
    Spent -> case makePair pk d of
        (a, ai) -> ((a, ai), BlindedKey pk (next refresh a ai))
  where
    n = private_n pk
    next k a ai
        | k > 1 = Pair (k - 1) ((a * a) `mod` n) ((ai * ai) `mod` n)
        | otherwise = Spent

-- | The decryption primitive, blinded with a given pair.
dpWithPair :: ByteArray ba => (Integer, Integer) -> PrivateKey -> ba -> ba
dpWithPair (a, ai) pk c = i2ospOf_ k ((ai * os2ip m) `mod` n)
  where
    n = private_n pk
    k = private_size pk
    m = dp Nothing pk (i2ospOf_ k ((a * os2ip c) `mod` n) `asTypeOf` c)

-- | The decryption primitive, blinded with the key's pair, and the key for
-- the next operation.  Randomness is drawn only when a new pair is due.
dpBlinded
    :: (MonadRandom m, ByteArray ba) => BlindedKey -> ba -> m (ba, BlindedKey)
dpBlinded bk c = do
    d <- case blindedPair bk of
        Pair {} -> return (Draw 0 0)
        Spent -> drawFor (blindedPrivateKey bk)
    let (pair, bk') = takePair d bk
    return (dpWithPair pair (blindedPrivateKey bk) c, bk')

-- | Run an operation with the pair kept for a key, for the functions that
-- take a bare t'PrivateKey'.  One t'BlindedKey' is kept per public key, for
-- the last few keys used; taking its pair and leaving the next is atomic, so
-- no two operations get the same pair.  The caller draws every time, since
-- whether a new pair is due is known only in here.
withBlindingFor :: PrivateKey -> Draw -> ((Integer, Integer) -> a) -> a
withBlindingFor pk d f = unsafePerformIO $ do
    pair <- atomicModifyIORef' table step
    return (f pair)
  where
    pub = private_pub pk
    step ks = case break ((== pub) . private_pub . blindedPrivateKey) ks of
        (before, bk : after) -> found bk (before ++ after)
        _ -> found (blindedKey pk) ks
    found bk rest = case takePair d bk of
        (pair@(!_, !_), bk') -> (take tableSize (bk' : rest), pair)
{-# NOINLINE withBlindingFor #-}

-- | How many keys 'withBlindingFor' remembers.
tableSize :: Int
tableSize = 4

table :: IORef [BlindedKey]
table = unsafePerformIO (newIORef [])
{-# NOINLINE table #-}
