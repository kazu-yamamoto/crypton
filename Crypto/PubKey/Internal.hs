-- |
-- Module      : Crypto.PubKey.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.PubKey.Internal (
    and',
    (&&!),
    dsaTruncHash,
    dsaTruncHashDigest,
    getHashAlg,
    rfc6979Nonce,
) where

import Data.Bits (shiftR)
import qualified Data.List as L

import Crypto.Hash
import Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Number.Basic (numBits)
import Crypto.Number.Generate (generatePrefix)
import Crypto.Number.Serialize
import Crypto.Random.HmacDRG (initial, update)
import Crypto.Random.Types (withDRG)

-- | This is a strict version of and
and' :: [Bool] -> Bool
and' l = L.foldl' (&&!) True l

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
True &&! True = True
True &&! False = False
False &&! True = False
False &&! False = False

-- | Truncate and hash for DSA and ECDSA.
dsaTruncHash
    :: (ByteArrayAccess msg, HashAlgorithm hash) => hash -> msg -> Integer -> Integer
dsaTruncHash hashAlg = dsaTruncHashDigest . hashWith hashAlg

-- | Truncate a digest for DSA and ECDSA.
dsaTruncHashDigest :: HashAlgorithm hash => Digest hash -> Integer -> Integer
dsaTruncHashDigest digest n
    | d > 0 = shiftR e d
    | otherwise = e
  where
    e = os2ip digest
    d = hashDigestSize (getHashAlg digest) * 8 - numBits n

getHashAlg :: Digest hash -> hash
getHashAlg _ = undefined

-- | The nonce of RFC 6979 for a group of order @n@ and private key @x@.
--
-- @extra@ is the additional input of RFC 6979 section 3.6, appended after
-- the digest: empty gives deterministic (EC)DSA, fresh random bytes give a
-- hedged nonce, which is distinct whenever either the randomness or the
-- message is.  @go@ answering 'Nothing' draws the next candidate.
rfc6979Nonce
    :: (HashAlgorithm hashDRG, HashAlgorithm hashDigest)
    => hashDRG
    -> Integer
    -> Integer
    -> Digest hashDigest
    -> ScrubbedBytes
    -> (Integer -> Maybe a)
    -> a
rfc6979Nonce alg n x digest extra go = fst $ withDRG state run
  where
    state = update seed $ initial alg
    -- int2octets(x) || bits2octets(h1) || k'
    seed = B.concat [i2ospOf_ bytes x, i2ospOf_ bytes h1, extra] :: ScrubbedBytes
    h1 = dsaTruncHashDigest digest n `mod` n
    run = do
        k <- generatePrefix bits
        if 0 < k && k < n then maybe run pure $ go k else run
    bytes = (bits + 7) `div` 8
    bits = numBits n
