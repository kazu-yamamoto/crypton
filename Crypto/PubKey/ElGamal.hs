{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.PubKey.ElGamal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- ElGamal encryption and signature over the multiplicative group of integers
-- modulo a prime, reusing the parameters of "Crypto.PubKey.DH".
--
-- /These are raw primitives, not a scheme./  The encryption here is textbook
-- ElGamal: it applies no padding, so it is malleable by construction --
-- multiplying a ciphertext's second component by @t@ multiplies the plaintext
-- by @t@ -- and it is not IND-CCA secure.  A message is an 'Integer' below the
-- modulus rather than a byte string, and nothing here maps one to the other.
-- Use it to build a scheme that adds those, or prefer
-- "Crypto.PubKey.RSA.OAEP" or "Crypto.PubKey.ECIES" where a scheme is what is
-- wanted.
--
-- The signature primitive is likewise raw, and an ephemeral value must never
-- be reused between signatures: two signatures under the same @k@ reveal the
-- private key.
--
-- == What is kept from the clock, and what is not
--
-- Every exponentiation with a secret exponent is
-- 'Crypto.Number.ModArithmetic.expSafe'.  Decryption inverts the shared
-- secret by Fermat's little theorem rather than by the extended Euclidean
-- algorithm, whose steps follow the bits it is given.  'sign' cannot do that
-- -- @k@ is inverted modulo @p-1@, which is even -- so it blinds instead: the
-- algorithm is handed @k@ times a fresh random unit, and the blinder is
-- divided out afterwards.  'signWith', having no randomness of its own, hands
-- it @k@.
--
-- What is left is the 'Integer' arithmetic around all of that, whose cost
-- follows the size of the numbers.  See "Crypto.PubKey.DSA" for the same note
-- at more length.
module Crypto.PubKey.ElGamal (
    Params,
    PublicNumber,
    PrivateNumber,
    EphemeralKey (..),
    SharedKey,
    Signature (..),

    -- * Generation
    generatePrivate,
    generatePublic,

    -- * Encryption and decryption with no scheme
    encryptWith,
    encrypt,
    decrypt,

    -- * Signature primitives
    signWith,
    sign,

    -- * Verification primitives
    verify,
) where

import Crypto.Error
import Crypto.Hash
import Crypto.Internal.ByteArray (ByteArrayAccess)
import Crypto.Internal.Imports
import Crypto.Number.Basic (gcde)
import Crypto.Number.Generate (generateBetween, generateMax)
import Crypto.Number.ModArithmetic (expFast, expSafe, inverse, inverseSafe)
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.DH (
    Params (..),
    PrivateNumber (..),
    PublicNumber (..),
    SharedKey (..),
 )
import Crypto.Random.Types
import Data.Data

-- | ElGamal Signature
data Signature = Signature
    { sign_r :: Integer
    -- ^ ElGamal r
    , sign_s :: Integer
    -- ^ ElGamal s
    }
    deriving (Show, Read, Eq, Data)

instance NFData Signature where
    rnf (Signature r s) = r `seq` s `seq` ()

-- | ElGamal Ephemeral key. also called Temporary key.
newtype EphemeralKey = EphemeralKey Integer
    deriving (NFData)

-- | generate a private number, in @[1, q-1]@ where @q@ is the order of the
-- group.  Zero is excluded: it would make the public number 1 and the shared
-- value constant.
generatePrivate :: MonadRandom m => Integer -> m PrivateNumber
generatePrivate q = PrivateNumber <$> generateBetween 1 (q - 1)

-- | generate a public number that is for the other party benefits.
-- this number is usually called h=g^a
generatePublic :: Params -> PrivateNumber -> PublicNumber
generatePublic (Params p g _) (PrivateNumber a) = PublicNumber $ expSafe g a p

-- | Is the other party's public number usable?
--
-- @1@ and @p-1@ generate a group of one or two elements, so the value they
-- mask the message with is one of a handful of constants.
validPublic :: Integer -> Integer -> Bool
validPublic p h = h > 1 && h < p - 1

-- | encrypt with a specified ephemeral key
--
-- The ephemeral key must lie in @[1, p-2]@ and must never be reused: zero
-- would leave the message unmasked, and a repeat lets anyone who learns one
-- plaintext recover the other.  A message must be below the modulus, or
-- decryption would return it reduced.
encryptWith
    :: EphemeralKey
    -> Params
    -> PublicNumber
    -> Integer
    -> CryptoFailable (Integer, Integer)
encryptWith (EphemeralKey b) (Params p g _) (PublicNumber h) m
    | b < 1 || b > p - 2 = CryptoFailed CryptoError_ParameterInvalid
    | not (validPublic p h) = CryptoFailed CryptoError_ParameterInvalid
    | m < 0 || m >= p = CryptoFailed CryptoError_ParameterInvalid
    | otherwise = CryptoPassed (c1, c2)
  where
    s = expSafe h b p
    c1 = expSafe g b p
    c2 = (s * m) `mod` p

-- | encrypt a message using params and public keys
-- will generate b (called the ephemeral key)
encrypt
    :: MonadRandom m
    => Params
    -> PublicNumber
    -> Integer
    -> m (CryptoFailable (Integer, Integer))
encrypt params@(Params p _ _) public m
    | p < 5 = return (CryptoFailed CryptoError_ParameterInvalid)
    | otherwise = do
        b <- generateBetween 1 (p - 2)
        return $ encryptWith (EphemeralKey b) params public m

-- | decrypt message
--
-- @c1@ must be a unit modulo @p@; a ciphertext whose first component is zero
-- or out of range is rejected rather than raising.
decrypt
    :: Params -> PrivateNumber -> (Integer, Integer) -> CryptoFailable Integer
decrypt (Params p _ _) (PrivateNumber a) (c1, c2)
    | c1 <= 0 || c1 >= p = CryptoFailed CryptoError_ParameterInvalid
    | c2 < 0 || c2 >= p = CryptoFailed CryptoError_ParameterInvalid
    | otherwise = case inverseSafe s p of
        Nothing -> CryptoFailed CryptoError_ParameterInvalid
        Just sm1 -> CryptoPassed ((c2 * sm1) `mod` p)
  where
    -- the shared secret, which the extended Euclidean algorithm would take
    -- apart: its steps follow the bits of what it is given, and this one is
    -- worth the private number.  p is prime, so Fermat gives the inverse
    -- without reading it
    s = expSafe c1 a p

-- | sign a message with an explicit ephemeral value
--
-- @k@ has to lie in @[1, p-2]@ and be coprime with @p-1@.  'Nothing' says the
-- value handed in cannot be used: either it fails one of those two conditions,
-- or it is one of the few that produce a second component of zero.  Either way
-- the answer is to draw another @k@, which is what 'sign' does.
--
-- @k@ is an ephemeral private key.  It has to be drawn uniformly at random,
-- kept secret, and used for one signature only: the private number follows
-- from a signature and its @k@, and equally from two signatures made with the
-- same @k@.  None of that is visible to this function, which is why it takes
-- @k@ from the caller and checks only what it can.
signWith
    :: (ByteArrayAccess msg, HashAlgorithm hash)
    => Integer
    -- ^ ephemeral value k, in [1, p-2] and coprime with p-1
    -> Params
    -- ^ DH params (p,g)
    -> PrivateNumber
    -- ^ DH private key
    -> hash
    -- ^ collision resistant hash algorithm
    -> msg
    -- ^ message to sign
    -> Maybe Signature
signWith = signWithBlinder 1

-- | The same with a blinder for the inversion of @k@.
--
-- @k@ is inverted modulo @p-1@, which is even, so Fermat's little theorem
-- does not reach it the way it reaches DSA's @k@ modulo a prime order: the
-- extended Euclidean algorithm is the only way there, and its steps follow
-- the bits of what it is given.  What can be done instead is to hand it
-- something else: for a unit @b@, the inverse of @k*b@ times @b@ is the
-- inverse of @k@, and the steps then follow @k*b@, which is a fresh random
-- number.  A blinder of 1 is no blinding, which is what the exported
-- 'signWith' has to do, having no randomness of its own.
--
-- When @b@ shares a factor with @p-1@ the algorithm reports it the same way
-- it reports one in @k@, and the answer is the same: draw again.
signWithBlinder
    :: (ByteArrayAccess msg, HashAlgorithm hash)
    => Integer -> Integer -> Params -> PrivateNumber -> hash -> msg -> Maybe Signature
signWithBlinder b k (Params p g _) (PrivateNumber x) hashAlg msg
    | k <= 0 || k >= p - 1 || b <= 0 || d > 1 = Nothing
    | s == 0 = Nothing
    | otherwise = Just $ Signature r s
  where
    r = expSafe g k p
    h = os2ip $ hashWith hashAlg msg
    s = ((h - x * r) * kInv) `mod` (p - 1)
    kInv = (kbInv * b) `mod` (p - 1)
    (kbInv, _, d) = gcde ((k * b) `mod` (p - 1)) (p - 1)

-- | sign message
--
-- This function draws the ephemeral value itself, and draws a fresh one on
-- each attempt until 'signWith' accepts it, so a caller who has no particular
-- @k@ in mind should use this rather than 'signWith'.
sign
    :: (ByteArrayAccess msg, HashAlgorithm hash, MonadRandom m)
    => Params
    -- ^ DH params (p,g)
    -> PrivateNumber
    -- ^ DH private key
    -> hash
    -- ^ collision resistant hash algorithm
    -> msg
    -- ^ message to sign
    -> m Signature
sign params@(Params p _ _) priv hashAlg msg = do
    k <- generateMax (p - 1)
    -- and a blinder for the inversion of k, which is the one step here that
    -- the extended Euclidean algorithm has to do
    b <- generateMax (p - 1)
    case signWithBlinder b k params priv hashAlg msg of
        Nothing -> sign params priv hashAlg msg
        Just sig -> return sig

-- | verify a signature
verify
    :: (ByteArrayAccess msg, HashAlgorithm hash)
    => Params
    -> PublicNumber
    -> hash
    -> msg
    -> Signature
    -> Bool
verify (Params p g _) (PublicNumber y) hashAlg msg (Signature r s)
    | or [r <= 0, r >= p, s <= 0, s >= (p - 1)] = False
    | otherwise = lhs == rhs
  where
    h = os2ip $ hashWith hashAlg msg
    lhs = expFast g h p
    rhs = (expFast y r p * expFast r s p) `mod` p
