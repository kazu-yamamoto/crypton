{-# LANGUAGE DeriveDataTypeable #-}

-- |
-- Module      : Crypto.PubKey.Rabin.RW
-- License     : BSD-style
-- Maintainer  : Carlos Rodriguez-Vega <crodveg@yahoo.es>
-- Stability   : experimental
-- Portability : unknown
--
-- Rabin-Williams cryptosystem for public-key encryption and digital signature.
-- See pages 323 - 324 in "Computational Number Theory and Modern Cryptography" by Song Y. Yan.
-- Also inspired by https://github.com/vanilala/vncrypt/blob/master/vncrypt/vnrw_gmp.c.
-- The Jacobi symbols here are taken modulo the public modulus, not the
-- private primes, so what "Crypto.PubKey.Rabin.Basic" says about that does
-- not apply; the note there about 'Integer' arithmetic does.
module Crypto.PubKey.Rabin.RW (
    PublicKey (..),
    PrivateKey (..),
    generate,
    encrypt,
    encryptWithSeed,
    decrypt,
    sign,
    verify,
) where

import Crypto.Debug (DebugShow (..))
import Data.ByteString
import Data.Data

import Crypto.Hash
import Crypto.Number.Basic (numBytes)
import Crypto.Number.ModArithmetic (expSafe, jacobi)
import Crypto.Number.Serialize (i2osp, i2ospOf_, os2ip)
import Crypto.PubKey.Rabin.OAEP
import Crypto.PubKey.Rabin.Types
import Crypto.Random.Types

-- | Represent a Rabin-Williams public key.
data PublicKey = PublicKey
    { public_size :: Int
    -- ^ size of key in bytes
    , public_n :: Integer
    -- ^ public p*q
    }
    deriving (Show, Read, Eq, Data)

-- | Represent a Rabin-Williams private key.
data PrivateKey = PrivateKey
    { private_pub :: PublicKey
    , private_p :: Integer
    -- ^ p prime number
    , private_q :: Integer
    -- ^ q prime number
    , private_d :: Integer
    }
    deriving (Read, Eq, Data)

-- | The public part is shown; the secret fields are not.  Use
-- 'Crypto.Debug.debugShow' to see them.
instance Show PrivateKey where
    showsPrec d k =
        showParen (d > 10) $
            showString "PrivateKey {private_pub = "
                . shows (private_pub k)
                . showString ", private_p = <secret>, private_q = <secret>, private_d = <secret>}"

instance DebugShow PrivateKey where
    debugShow k =
        showString "PrivateKey {private_pub = "
            . shows (private_pub k)
            . showString ", private_p = "
            . shows (private_p k)
            . showString ", private_q = "
            . shows (private_q k)
            . showString ", private_d = "
            . shows (private_d k)
            . showChar '}'
            $ ""

-- | Generate a pair of (private, public) key of size in bytes.
-- Prime p is congruent 3 mod 8 and prime q is congruent 7 mod 8.
generate
    :: MonadRandom m
    => Int
    -> m (PublicKey, PrivateKey)
generate size = do
    (p, q) <- generatePrimes size (\p -> p `mod` 8 == 3) (\q -> q `mod` 8 == 7)
    return (generateKeys p q)
  where
    generateKeys p q =
        let n = p * q
            d = ((p - 1) * (q - 1) `div` 4 + 1) `div` 2
            publicKey =
                PublicKey
                    { public_size = size
                    , public_n = n
                    }
            privateKey =
                PrivateKey
                    { private_pub = publicKey
                    , private_p = p
                    , private_q = q
                    , private_d = d
                    }
         in (publicKey, privateKey)

-- | Encrypt plaintext using public key an a predefined OAEP seed.
--
-- See algorithm 8.11 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
encryptWithSeed
    :: HashAlgorithm hash
    => ByteString
    -- ^ Seed
    -> OAEPParams hash ByteString ByteString
    -- ^ OAEP padding
    -> PublicKey
    -- ^ public key
    -> ByteString
    -- ^ plaintext
    -> Either Error ByteString
encryptWithSeed seed oaep pk m =
    let n = public_n pk
        k = numBytes n
     in do
            m' <- pad seed oaep k m
            m'' <- ep1 n $ os2ip m'
            return $ i2osp $ ep2 n m''

-- | Encrypt plaintext using public key.
encrypt
    :: (HashAlgorithm hash, MonadRandom m)
    => OAEPParams hash ByteString ByteString
    -- ^ OAEP padding parameters
    -> PublicKey
    -- ^ public key
    -> ByteString
    -- ^ plaintext
    -> m (Either Error ByteString)
encrypt oaep pk m = do
    seed <- getRandomBytes hashLen
    return $ encryptWithSeed seed oaep pk m
  where
    hashLen = hashDigestSize (oaepHash oaep)

-- | Decrypt ciphertext using private key.
--
-- The ciphertext has to be what 'encrypt' produces: the big-endian encoding,
-- with no leading zero octet, of a value below the modulus.  The primitives
-- work modulo n, so without that condition @c@ and @c + n@ -- and @c@ with a
-- zero octet in front of it -- would all decrypt to the same message, and a
-- ciphertext would not be unique to its plaintext.
decrypt
    :: HashAlgorithm hash
    => OAEPParams hash ByteString ByteString
    -- ^ OAEP padding parameters
    -> PrivateKey
    -- ^ private key
    -> ByteString
    -- ^ ciphertext
    -> Maybe ByteString
decrypt oaep pk c
    | os2ip c >= public_n (private_pub pk) = Nothing
    | c /= (i2osp (os2ip c) :: ByteString) = Nothing
    | otherwise =
        let d = private_d pk
            n = public_n $ private_pub pk
            k = numBytes n
            c' = i2ospOf_ k $ dp2 n $ dp1 d n $ os2ip c
         in case unpad oaep k c' of
                Left _ -> Nothing
                Right p -> Just p

-- | Sign message using hash algorithm and private key.
sign
    :: HashAlgorithm hash
    => PrivateKey
    -- ^ private key
    -> hash
    -- ^ hash function
    -> ByteString
    -- ^ message to sign
    -> Either Error Integer
sign pk hashAlg m =
    let d = private_d pk
        n = public_n $ private_pub pk
     in do
            m' <- ep1 n $ os2ip $ hashWith hashAlg m
            return $ dp1 d n m'

-- | Verify signature using hash algorithm and public key.
verify
    :: HashAlgorithm hash
    => PublicKey
    -- ^ public key
    -> hash
    -- ^ hash function
    -> ByteString
    -- ^ message
    -> Integer
    -- ^ signature
    -> Bool
verify pk hashAlg m s
    -- squaring works modulo n, so s + n and -s would verify wherever s does
    | s < 0 || s >= n = False
    | otherwise =
        let h = os2ip $ hashWith hashAlg m
            h' = dp2 n $ ep2 n s
         in h' == h
  where
    n = public_n pk

-- | Encryption primitive 1
ep1 :: Integer -> Integer -> Either Error Integer
ep1 n m =
    let m' = 2 * m + 1
        m'' = 2 * m'
        m''' = 2 * m''
     in case jacobi m' n of
            Just (-1) | m'' < n -> Right m''
            Just 1 | m''' < n -> Right m'''
            _ -> Left InvalidParameters

-- | Encryption primitive 2
ep2 :: Integer -> Integer -> Integer
ep2 n m = expSafe m 2 n

-- | Decryption primitive 1
dp1 :: Integer -> Integer -> Integer -> Integer
dp1 d n c = expSafe c d n

-- | Decryption primitive 2
dp2 :: Integer -> Integer -> Integer
dp2 n c =
    let c' = c `div` 2
        c'' = (n - c) `div` 2
     in case c `mod` 4 of
            0 -> ((c' `div` 2 - 1) `div` 2)
            1 -> ((c'' `div` 2 - 1) `div` 2)
            2 -> ((c' - 1) `div` 2)
            _ -> ((c'' - 1) `div` 2)
