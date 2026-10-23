-- |
-- Module      : Crypto.PubKey.RSA.PSS
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.PubKey.RSA.PSS (
    PSSParams (..),
    defaultPSSParams,
    defaultPSSParamsSHA1,

    -- * Sign and verify functions
    signWithSalt,
    signDigestWithSalt,
    sign,
    signDigest,
    signSafer,
    signDigestSafer,
    signBlinded,
    signDigestBlinded,
    verify,
    verifyDigest,
) where

import Crypto.Hash
import Crypto.Number.Basic (numBits)
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.MaskGenFunction
import Crypto.PubKey.RSA.Blinded.Internal
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types
import Crypto.Random.Types
import Data.Bits (complement, shiftR, (.&.))
import Data.Word

import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B (bxor, convert, eq)

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- | Parameters for PSS signature/verification.
data PSSParams hash seed output = PSSParams
    { pssHash :: hash
    -- ^ Hash function to use
    , pssMaskGenAlg :: MaskGenAlgorithm seed output
    -- ^ Mask Gen algorithm to use
    , pssSaltLength :: Int
    -- ^ Length of salt. need to be <= to hLen.
    , pssTrailerField :: Word8
    -- ^ Trailer field, usually 0xbc
    }

-- | Default Params with a specified hash function
defaultPSSParams
    :: (ByteArrayAccess seed, ByteArray output, HashAlgorithm hash)
    => hash
    -> PSSParams hash seed output
defaultPSSParams hashAlg =
    PSSParams
        { pssHash = hashAlg
        , pssMaskGenAlg = mgf1 hashAlg
        , pssSaltLength = hashDigestSize hashAlg
        , pssTrailerField = 0xbc
        }

-- | Default Params using SHA1 algorithm.
defaultPSSParamsSHA1 :: PSSParams SHA1 ByteString ByteString
defaultPSSParamsSHA1 = defaultPSSParams SHA1

-- | Sign using the PSS parameters and the salt explicitely passed as parameters.
--
-- the function ignore SaltLength from the PSS Parameters
--
-- See t'Blinder' for what the optional blinder covers and when leaving it out
-- is a decision rather than a default.  'signSafer' generates one for you.
signDigestWithSalt
    :: HashAlgorithm hash
    => ByteString
    -- ^ Salt to use
    -> Maybe Blinder
    -- ^ optional blinder to use
    -> PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use
    -> PrivateKey
    -- ^ RSA Private Key
    -> Digest hash
    -- ^ Message digest
    -> Either Error ByteString
signDigestWithSalt salt blinder params pk digest =
    dp blinder pk <$> encodeDigest salt params pk digest

-- | The encoded message the private-key operation is applied to.
encodeDigest
    :: HashAlgorithm hash
    => ByteString
    -> PSSParams hash ByteString ByteString
    -> PrivateKey
    -> Digest hash
    -> Either Error ByteString
encodeDigest salt params pk digest
    | emLen < hashLen + saltLen + 2 = Left InvalidParameters
    | otherwise = Right em
  where
    k = private_size pk
    emLen = if emTruncate pubBits then k - 1 else k
    mHash = B.convert digest
    dbLen = emLen - hashLen - 1
    saltLen = B.length salt
    hashLen = hashDigestSize (pssHash params)
    pubBits = numBits (private_n pk)
    m' = B.concat [B.replicate 8 0, mHash, salt]
    h = B.convert $ hashWith (pssHash params) m'
    db = B.concat [B.replicate (dbLen - saltLen - 1) 0, B.singleton 1, salt]
    dbmask = pssMaskGenAlg params h dbLen
    maskedDB = normalizeToKeySize pubBits (B.bxor db dbmask :: ByteString)
    em = B.concat [maskedDB, h, B.singleton (pssTrailerField params)]

-- | Sign using the PSS parameters and the salt explicitely passed as parameters.
--
-- the function ignore SaltLength from the PSS Parameters
--
-- See t'Blinder' for what the optional blinder covers and when leaving it out
-- is a decision rather than a default.  'signSafer' generates one for you.
signWithSalt
    :: HashAlgorithm hash
    => ByteString
    -- ^ Salt to use
    -> Maybe Blinder
    -- ^ optional blinder to use
    -> PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use
    -> PrivateKey
    -- ^ RSA Private Key
    -> ByteString
    -- ^ Message to sign
    -> Either Error ByteString
signWithSalt salt blinder params pk m = signDigestWithSalt salt blinder params pk mHash
  where
    mHash = hashWith (pssHash params) m

-- | Sign using the PSS Parameters
--
-- See t'Blinder' for what the optional blinder covers and when leaving it out
-- is a decision rather than a default.  'signSafer' generates one for you.
sign
    :: (HashAlgorithm hash, MonadRandom m)
    => Maybe Blinder
    -- ^ optional blinder to use
    -> PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use
    -> PrivateKey
    -- ^ RSA Private Key
    -> ByteString
    -- ^ Message to sign
    -> m (Either Error ByteString)
sign blinder params pk m = do
    salt <- getRandomBytes (pssSaltLength params)
    return (signWithSalt salt blinder params pk m)

-- | Sign using the PSS Parameters
--
-- See t'Blinder' for what the optional blinder covers and when leaving it out
-- is a decision rather than a default.  'signSafer' generates one for you.
signDigest
    :: (HashAlgorithm hash, MonadRandom m)
    => Maybe Blinder
    -- ^ optional blinder to use
    -> PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use
    -> PrivateKey
    -- ^ RSA Private Key
    -> Digest hash
    -- ^ Message digest
    -> m (Either Error ByteString)
signDigest blinder params pk digest = do
    salt <- getRandomBytes (pssSaltLength params)
    return (signDigestWithSalt salt blinder params pk digest)

-- | Sign using the PSS Parameters, blinded with the pair kept for this key;
-- see "Crypto.PubKey.RSA.Blinded".
signSafer
    :: (HashAlgorithm hash, MonadRandom m)
    => PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use
    -> PrivateKey
    -- ^ private key
    -> ByteString
    -- ^ message to sign
    -> m (Either Error ByteString)
signSafer params pk m = signDigestSafer params pk (hashWith (pssHash params) m)

-- | Sign using the PSS Parameters, blinded with the pair kept for this key;
-- see "Crypto.PubKey.RSA.Blinded".
signDigestSafer
    :: (HashAlgorithm hash, MonadRandom m)
    => PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use
    -> PrivateKey
    -- ^ private key
    -> Digest hash
    -- ^ message digst
    -> m (Either Error ByteString)
signDigestSafer params pk digest = do
    salt <- getRandomBytes (pssSaltLength params)
    d <- drawFor pk
    return $ case encodeDigest salt params pk digest of
        Left err -> Left err
        Right em -> Right (withBlindingFor pk d (\pair -> dpWithPair pair pk em))

-- | 'signSafer' with the blinding a t'BlindedKey' keeps, and the key for the
-- next operation.
signBlinded
    :: (HashAlgorithm hash, MonadRandom m)
    => PSSParams hash ByteString ByteString
    -> BlindedKey
    -> ByteString
    -- ^ message to sign
    -> m (Either Error ByteString, BlindedKey)
signBlinded params bk m = signDigestBlinded params bk (hashWith (pssHash params) m)

-- | 'signDigestSafer' with the blinding a t'BlindedKey' keeps, and the key
-- for the next operation.
signDigestBlinded
    :: (HashAlgorithm hash, MonadRandom m)
    => PSSParams hash ByteString ByteString
    -> BlindedKey
    -> Digest hash
    -- ^ message digest
    -> m (Either Error ByteString, BlindedKey)
signDigestBlinded params bk digest = do
    salt <- getRandomBytes (pssSaltLength params)
    case encodeDigest salt params (blindedPrivateKey bk) digest of
        Left err -> return (Left err, bk)
        Right em -> do
            (s, bk') <- dpBlinded bk em
            return (Right s, bk')

-- | Verify a signature using the PSS Parameters
verify
    :: HashAlgorithm hash
    => PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use to verify,
    --   this need to be identical to the parameters when signing
    -> PublicKey
    -- ^ RSA Public Key
    -> ByteString
    -- ^ Message to verify
    -> ByteString
    -- ^ Signature
    -> Bool
verify params pk m = verifyDigest params pk mHash
  where
    mHash = hashWith (pssHash params) m

-- | Verify a signature using the PSS Parameters
--
-- Following RFC 8017, the signature is rejected unless it is exactly as long
-- as the modulus (section 8.1.2, step 1) and its integer representative is
-- below the modulus (RSAVP1, section 5.2.2, step 1).  The public-key operation
-- normalises any multiple of the modulus away, so without the second check
-- @s + n@ would verify as readily as @s@, and a third party could turn one
-- valid signature into another without the private key.
verifyDigest
    :: HashAlgorithm hash
    => PSSParams hash ByteString ByteString
    -- ^ PSS Parameters to use to verify,
    --   this need to be identical to the parameters when signing
    -> PublicKey
    -- ^ RSA Public Key
    -> Digest hash
    -- ^ Digest to verify
    -> ByteString
    -- ^ Signature
    -> Bool
verifyDigest params pk digest s
    | B.length s /= k = False
    | os2ip s >= public_n pk = False
    | B.any (/= 0) pre = False
    | B.any (\x -> x .&. topBits /= 0) (B.take 1 maskedDB) = False
    | B.last em /= pssTrailerField params = False
    | B.any (/= 0) ps0 = False
    | b1 /= B.singleton 1 = False
    | pssSaltLength params /= B.length salt = False
    | otherwise = B.eq h h'
  where
    -- parameters
    hashLen = hashDigestSize (pssHash params)
    mHash = B.convert digest
    k = public_size pk
    emLen = if emTruncate pubBits then k - 1 else k
    dbLen = emLen - hashLen - 1
    pubBits = numBits (public_n pk)
    -- RFC 8017 9.1.2 step 6: the leftmost 8*emLen - emBits bits of the
    -- leftmost octet of maskedDB have to be zero already.  Step 9 clears
    -- them in DB, which is what normalizeToKeySize does below, and clearing
    -- is not checking: without this an encoding with the top bit set -- one
    -- the standard calls inconsistent -- verifies as though it were sound,
    -- because the bit that made it wrong is thrown away before it is read.
    topBits = complement (normalizeMask pubBits)
    -- unmarshall fields
    (pre, em) = B.splitAt (k - emLen) (ep pk s) -- drop 0..1 byte
    maskedDB = B.take dbLen em
    h = B.take hashLen $ B.drop (B.length maskedDB) em
    dbmask = pssMaskGenAlg params h dbLen
    db = normalizeToKeySize pubBits (B.bxor maskedDB dbmask :: ByteString)
    (ps0, z) = B.break (== 1) db
    (b1, salt) = B.splitAt 1 z
    m' = B.concat [B.replicate 8 0, mHash, salt]
    h' = hashWith (pssHash params) m'

-- When the modulus has bit length 1 modulo 8 we drop the first byte.
emTruncate :: Int -> Bool
emTruncate bits = ((bits - 1) .&. 0x7) == 0

normalizeToKeySize :: Int -> ByteString -> ByteString
normalizeToKeySize bits x = case B.uncons x of
    Nothing -> x -- very unlikely
    Just (h, t) -> B.cons (h .&. normalizeMask bits) t

-- | The bits of the leftmost octet that belong to the encoding: the low
-- @emBits `mod` 8@ of them, or all eight when that is zero.  Its complement
-- is the bits RFC 8017 requires to be zero.
normalizeMask :: Int -> Word8
normalizeMask bits = if sh > 0 then 0xff `shiftR` (8 - sh) else 0xff
  where
    sh = (bits - 1) .&. 0x7
