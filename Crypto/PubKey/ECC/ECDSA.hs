{-# LANGUAGE DeriveDataTypeable #-}

-- | /WARNING:/ Signature operations may leak the private key. Signature verification
-- should be safe.
module Crypto.PubKey.ECC.ECDSA (
    Signature (..),
    ExtendedSignature (..),
    PublicPoint,
    PublicKey (..),
    PrivateNumber,
    PrivateKey (..),
    KeyPair (..),
    toPublicKey,
    toPrivateKey,
    signWith,
    signDigestWith,
    signExtendedDigestWith,
    sign,
    signDigest,
    signExtendedDigest,
    verify,
    verifyDigest,
    recover,
    recoverDigest,
    deterministicNonce,
) where

import Control.Monad
import Data.Data
import Data.Bits
import Data.ByteArray (ByteArrayAccess, ScrubbedBytes)

import Crypto.Hash
import Crypto.Number.Basic
import Crypto.Number.Generate
import Crypto.Number.Serialize
import Crypto.Number.ModArithmetic (inverse)
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.Internal (dsaTruncHashDigest)
import Crypto.Random.Types
import Crypto.Random.HmacDRG

-- | Represent a ECDSA signature namely R and S.
data Signature = Signature
    { sign_r :: Integer
    -- ^ ECDSA r
    , sign_s :: Integer
    -- ^ ECDSA s
    }
    deriving (Show, Read, Eq, Data)

-- | ECDSA signature with public key recovery information.
data ExtendedSignature = ExtendedSignature
    { index :: Integer
    -- ^ Index of the X coordinate
    , parity :: Bool
    -- ^ Parity of the Y coordinate
    , signature :: Signature
    -- ^ Inner signature
    }
    deriving (Show, Read, Eq, Data)

-- | ECDSA Private Key.
data PrivateKey = PrivateKey
    { private_curve :: Curve
    , private_d :: PrivateNumber
    }
    deriving (Show, Read, Eq, Data)

-- | ECDSA Public Key.
data PublicKey = PublicKey
    { public_curve :: Curve
    , public_q :: PublicPoint
    }
    deriving (Show, Read, Eq, Data)

-- | ECDSA Key Pair.
data KeyPair = KeyPair Curve PublicPoint PrivateNumber
    deriving (Show, Read, Eq, Data)

-- | Public key of a ECDSA Key pair.
toPublicKey :: KeyPair -> PublicKey
toPublicKey (KeyPair curve pub _) = PublicKey curve pub

-- | Private key of a ECDSA Key pair.
toPrivateKey :: KeyPair -> PrivateKey
toPrivateKey (KeyPair curve _ priv) = PrivateKey curve priv

-- | Sign digest using the private key and an explicit k number.
--
-- /WARNING:/ Vulnerable to timing attacks.
signExtendedDigestWith
    :: HashAlgorithm hash
    => Integer
    -- ^ k random number
    -> PrivateKey
    -- ^ private key
    -> Digest hash
    -- ^ digest to sign
    -> Maybe ExtendedSignature
signExtendedDigestWith k (PrivateKey curve d) digest = do
    let z = dsaTruncHashDigest digest n
        CurveCommon _ _ g n _ = common_curve curve
    (i, r, p) <- pointDecompose curve $ pointMul curve k g
    kInv <- inverse k n
    let s = kInv * (z + r * d) `mod` n
    when (r == 0 || s == 0) Nothing
    return $ if s <= n `unsafeShiftR` 1
        then ExtendedSignature i p $ Signature r s
        else ExtendedSignature i (not p) $ Signature r (n - s)

-- | Sign digest using the private key and an explicit k number.
--
-- /WARNING:/ Vulnerable to timing attacks.
signDigestWith
    :: HashAlgorithm hash
    => Integer
    -- ^ k random number
    -> PrivateKey
    -- ^ private key
    -> Digest hash
    -- ^ digest to sign
    -> Maybe Signature
signDigestWith k pk digest = signature <$> signExtendedDigestWith k pk digest

-- | Sign message using the private key and an explicit k number.
--
-- /WARNING:/ Vulnerable to timing attacks.
signWith
    :: (ByteArrayAccess msg, HashAlgorithm hash)
    => Integer
    -- ^ k random number
    -> PrivateKey
    -- ^ private key
    -> hash
    -- ^ hash function
    -> msg
    -- ^ message to sign
    -> Maybe Signature
signWith k pk hashAlg msg = signDigestWith k pk (hashWith hashAlg msg)

-- | Sign digest using the private key.
--
-- /WARNING:/ Vulnerable to timing attacks.
signExtendedDigest
    :: (HashAlgorithm hash, MonadRandom m)
    => PrivateKey -> Digest hash -> m ExtendedSignature
signExtendedDigest pk digest = do
    k <- generateBetween 1 (n - 1)
    case signExtendedDigestWith k pk digest of
        Nothing -> signExtendedDigest pk digest
        Just sig -> return sig
  where
    n = ecc_n . common_curve $ private_curve pk

-- | Sign digest using the private key.
--
-- /WARNING:/ Vulnerable to timing attacks.
signDigest
    :: (HashAlgorithm hash, MonadRandom m)
    => PrivateKey -> Digest hash -> m Signature
signDigest pk digest = signature <$> signExtendedDigest pk digest

-- | Sign message using the private key.
--
-- /WARNING:/ Vulnerable to timing attacks.
sign
    :: (ByteArrayAccess msg, HashAlgorithm hash, MonadRandom m)
    => PrivateKey -> hash -> msg -> m Signature
sign pk hashAlg msg = signDigest pk (hashWith hashAlg msg)

-- | Verify a digest using the public key.
verifyDigest
    :: HashAlgorithm hash => PublicKey -> Signature -> Digest hash -> Bool
verifyDigest (PublicKey _ PointO) _ _ = False
verifyDigest pk@(PublicKey curve q) (Signature r s) digest
    | r < 1 || r >= n || s < 1 || s >= n = False
    | otherwise = maybe False (r ==) $ do
        w <- inverse s n
        let z = dsaTruncHashDigest digest n
            u1 = z * w `mod` n
            u2 = r * w `mod` n
            x = pointAddTwoMuls curve u1 g u2 q
        case x of
            PointO -> Nothing
            Point x1 _ -> return $ x1 `mod` n
  where
    n = ecc_n cc
    g = ecc_g cc
    cc = common_curve $ public_curve pk

-- | Verify a bytestring using the public key.
verify
    :: (ByteArrayAccess msg, HashAlgorithm hash)
    => hash -> PublicKey -> Signature -> msg -> Bool
verify hashAlg pk sig msg = verifyDigest pk sig (hashWith hashAlg msg)

-- | Recover the public key from an extended signature and a digest.
recoverDigest
    :: HashAlgorithm hash
    => Curve -> ExtendedSignature -> Digest hash -> Maybe PublicKey
recoverDigest curve (ExtendedSignature i p (Signature r s)) digest = do
    let CurveCommon _ _ g n _ = common_curve curve
    let z = dsaTruncHashDigest digest n
    w <- inverse r n
    c <- pointCompose curve i r p
    pure $ PublicKey curve $ pointAddTwoMuls curve (s * w) c (negate $ z * w) g

-- | Recover the public key from an extended signature and a message.
recover
    :: (ByteArrayAccess msg, HashAlgorithm hash)
    => hash -> Curve -> ExtendedSignature -> msg -> Maybe PublicKey
recover hashAlg curve sig msg = recoverDigest curve sig $ hashWith hashAlg msg

-- | Deterministic nonce generation according to RFC 6979.
-- Allows using different hash algorithms for the HMAC-based DRG and the message digest.
deterministicNonce
    :: (HashAlgorithm hashDRG, HashAlgorithm hashDigest)
    => hashDRG -> PrivateKey -> Digest hashDigest -> (Integer -> Maybe a) -> a
deterministicNonce alg (PrivateKey curve key) digest go = fst $ withDRG state run where
    state = update seed $ initial alg where
        seed = i2ospOf_ bytes key <> i2ospOf_ bytes message :: ScrubbedBytes
        message = dsaTruncHashDigest digest n `mod` n
    run = do
        k <- generatePrefix bits
        if 0 < k && k < n then maybe run pure $ go k else run
    bytes = (bits + 7) `unsafeShiftR` 3
    bits = numBits n
    n = ecc_n $ common_curve curve
