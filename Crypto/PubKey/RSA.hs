{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Crypto.PubKey.RSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.PubKey.RSA (
    Error (..),
    PublicKey (..),
    PrivateKey (..),
    Blinder (..),

    -- * Generation function
    generateWith,
    generate,
    generateBlinder,
) where

import Crypto.Internal.ByteArray (ScrubbedBytes)
import Crypto.Number.Generate (generateMax)
import Crypto.Number.ModArithmetic (
    expSafe,
    inverse,
    inverseCoprimes,
    inverseSafe,
 )
import Crypto.Number.Prime (generatePrime)
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.RSA.Types
import Crypto.Random.Types

{-
-- some bad implementation will not serialize ASN.1 integer properly, leading
-- to negative modulus.
-- TODO : Find a better place for this
toPositive :: Integer -> Integer
toPositive int
    | int < 0   = uintOfBytes $ bytesOfInt int
    | otherwise = int
  where uintOfBytes = foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0
        bytesOfInt :: Integer -> [Word8]
        bytesOfInt n = if testBit (head nints) 7 then nints else 0xff : nints
          where nints = reverse $ plusOne $ reverse $ map complement $ bytesOfUInt (abs n)
                plusOne []     = [1]
                plusOne (x:xs) = if x == 0xff then 0 : plusOne xs else (x+1) : xs
                bytesOfUInt x = reverse (list x)
                  where list i = if i <= 0xff then [fromIntegral i] else (fromIntegral i .&. 0xff) : list (i `shiftR` 8)
-}

-- | Generate a key pair given p and q.
--
-- p and q need to be distinct prime numbers.
--
-- e need to be coprime to phi=(p-1)*(q-1). If that's not the
-- case, the function will not return a key pair.
-- A small hamming weight results in better performance.
--
-- * e=0x10001 is a popular choice
--
-- * e=3 is popular as well, but proven to not be as secure for some cases.
--
-- /WARNING:/ Making a key is not constant time, and cannot be: the search for
-- the two primes takes as long as it takes, and 'Crypto.Number.Prime' is not
-- constant time either.  What that leaks is about the search rather than
-- about the primes it settles on.  Of the arithmetic that does touch them,
-- the inverse of one prime modulo the other is worked out without a side
-- channel, and so is the private exponent, which is the inverse of @e@ modulo
-- @(p-1)*(q-1)@: @e@ being public lets that be worked out as a remainder, an
-- inverse modulo @e@ itself, and an exact division, none of which follows the
-- number being inverted.  An @e@ that is not prime keeps the extended
-- Euclidean algorithm, which for a public @e@ is one division by a small
-- number and then a few steps on numbers under it.
generateWith
    :: (Integer, Integer)
    -- ^ chosen distinct primes p and q
    -> Int
    -- ^ size in bytes
    -> Integer
    -- ^ RSA public exponent 'e'
    -> Maybe (PublicKey, PrivateKey)
generateWith (p, q) size e =
    case privateExponent of
        Nothing -> Nothing
        Just d -> Just (pub, priv d)
  where
    n = p * q
    phi = (p - 1) * (q - 1)
    -- The private exponent is the inverse of e modulo phi, and phi is the
    -- key.  The extended Euclidean algorithm would take a number of steps
    -- that follows it; e being public lets the work be about e instead.
    --
    -- Whatever d is, e * d = 1 + k * phi for some k under e, and reading that
    -- modulo e gives k = -phi^-1 mod e -- an inverse modulo a number of a
    -- handful of bits, which for a prime e is Fermat.  Then d is an exact
    -- division by e.  Nothing in that follows phi: the remainder and the
    -- division are one pass each over its limbs, and the rest is arithmetic
    -- the size of e.
    --
    -- Fermat wants a prime e, and rather than ask whether e is one -- which
    -- costs more than everything else here -- the k it gives is checked,
    -- which is arithmetic the size of e.  A composite e that fails the check
    -- keeps the algorithm it had.
    privateExponent
        | e <= 1 = Nothing
        | t == 0 = Nothing -- e divides phi, so there is no inverse
        | (k * t) `mod` e == e - 1 = Just ((1 + k * phi) `div` e)
        | otherwise = inverse e phi
      where
        t = phi `mod` e
        k = (e - expSafe t (e - 2) e) `mod` e
    -- q and p should be *distinct* *prime* numbers, hence always coprime.
    -- Both of them are the key itself, so the inverse is worked out through
    -- Fermat's little theorem rather than the extended Euclidean algorithm,
    -- whose steps follow the numbers it is given.  It falls back on the one
    -- that raises, which is what a p that is not prime deserves.
    qinv = case inverseSafe q p of
        Just i -> i
        Nothing -> inverseCoprimes q p
    pub =
        PublicKey
            { public_size = size
            , public_n = n
            , public_e = e
            }
    priv d =
        PrivateKey
            { private_pub = pub
            , private_d = d
            , private_p = p
            , private_q = q
            , private_dP = d `mod` (p - 1)
            , private_dQ = d `mod` (q - 1)
            , private_qinv = qinv
            }

-- | generate a pair of (private, public) key of size in bytes.
generate
    :: MonadRandom m
    => Int
    -- ^ size in bytes
    -> Integer
    -- ^ RSA public exponent 'e'
    -> m (PublicKey, PrivateKey)
generate size e = loop
  where
    loop = do
        -- loop until we find a valid key pair given e
        pq <- generatePQ
        case generateWith pq size e of
            Nothing -> loop
            Just pp -> return pp
    generatePQ = do
        p <- generatePrime (8 * (size `div` 2))
        q <- generateQ p
        return (p, q)
    generateQ p = do
        q <- generatePrime (8 * (size - (size `div` 2)))
        if p == q then generateQ p else return q

-- | Generate a blinder to use with decryption and signing operation
--
-- the unique parameter apart from the random number generator is the
-- public key value N.
--
-- The blinder holds a random number and its inverse.  N is composite, so
-- Fermat has no answer for the inverse and it goes through the extended
-- Euclidean algorithm, whose steps follow the number handed to it -- which
-- would be the number the blinding rests on.  So the algorithm is handed that
-- number multiplied by another random one instead, and its answer multiplied
-- by that number again, which leaves the inverse wanted and shows the
-- algorithm nothing that has anything to do with it.
generateBlinder
    :: forall m
     . MonadRandom m
    => Integer
    -- ^ RSA public N parameter.
    -> m Blinder
generateBlinder n = do
    r <- generateMax n
    -- The inverse goes through the extended Euclidean algorithm, whose steps
    -- follow the number handed to it, and r is what the blinding rests on.
    -- So another random number goes with it: the product is uniform and says
    -- nothing about r on its own, and multiplying its inverse by that number
    -- again leaves the inverse of r.  Sixteen bytes are enough to hide it and
    -- are under either prime, so the product is coprime with n whenever r is,
    -- as it was before.
    u <- os2ip <$> (getRandomBytes 16 :: m ScrubbedBytes)
    let v = (r * u) `mod` n
        rm1 = (inverseCoprimes v n * u) `mod` n
    return $ Blinder r rm1
