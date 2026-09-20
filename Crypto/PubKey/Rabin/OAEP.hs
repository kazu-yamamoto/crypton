-- |
-- Module      : Crypto.PubKey.Rabin.OAEP
-- License     : BSD-style
-- Maintainer  : Carlos Rodriguez-Vega <crodveg@yahoo.es>
-- Stability   : experimental
-- Portability : unknown
--
-- OAEP padding scheme.
-- See <http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>.
module Crypto.PubKey.Rabin.OAEP (
    OAEPParams (..),
    defaultOAEPParams,
    pad,
    unpad,
) where

import Data.Bits (complement, shiftR, xor, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.List (foldl')
import Data.Word (Word32)
import Prelude hiding (foldl')

import Crypto.Hash
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B (constEq, convert)
import Crypto.PubKey.Internal (and')
import Crypto.PubKey.MaskGenFunction
import Crypto.PubKey.Rabin.Types

-- | Parameters for OAEP padding.
data OAEPParams hash seed output = OAEPParams
    { oaepHash :: hash
    -- ^ hash function to use
    , oaepMaskGenAlg :: MaskGenAlgorithm seed output
    -- ^ mask Gen algorithm to use
    , oaepLabel :: Maybe ByteString
    -- ^ optional label prepended to message
    }

-- | Default Params with a specified hash function.
defaultOAEPParams
    :: (ByteArrayAccess seed, ByteArray output, HashAlgorithm hash)
    => hash
    -> OAEPParams hash seed output
defaultOAEPParams hashAlg =
    OAEPParams
        { oaepHash = hashAlg
        , oaepMaskGenAlg = mgf1 hashAlg
        , oaepLabel = Nothing
        }

-- | Pad a message using OAEP.
pad
    :: HashAlgorithm hash
    => ByteString
    -- ^ Seed
    -> OAEPParams hash ByteString ByteString
    -- ^ OAEP params to use
    -> Int
    -- ^ size of public key in bytes
    -> ByteString
    -- ^ Message pad
    -> Either Error ByteString
pad seed oaep k msg
    | k < 2 * hashLen + 2 = Left InvalidParameters
    | B.length seed /= hashLen = Left InvalidParameters
    | mLen > k - 2 * hashLen - 2 = Left MessageTooLong
    | otherwise = Right em
  where
    -- parameters
    mLen = B.length msg
    mgf = oaepMaskGenAlg oaep
    labelHash = hashWith (oaepHash oaep) (maybe B.empty id $ oaepLabel oaep)
    hashLen = hashDigestSize (oaepHash oaep)
    -- put fields
    ps = B.replicate (k - mLen - 2 * hashLen - 2) 0
    db = B.concat [B.convert labelHash, ps, B.singleton 0x1, msg]
    dbmask = mgf seed (k - hashLen - 1)
    maskedDB = B.pack $ B.zipWith xor db dbmask
    seedMask = mgf maskedDB hashLen
    maskedSeed = B.pack $ B.zipWith xor seed seedMask
    em = B.concat [B.singleton 0x0, maskedSeed, maskedDB]

-- | Un-pad a OAEP encoded message.
--
-- The data block is scanned in full rather than up to the 01 octet separating
-- the padding from the message, and the label hash and the leading octet are
-- compared without an early exit, so neither the length of the padding nor
-- where a comparison first differs shows up in how long this takes.  This is
-- what "Crypto.PubKey.RSA.OAEP" does with the same block.
--
-- What remains visible is the result itself: whether the block was well formed,
-- and the length of the message when it was.  That is the signal Manger's
-- attack needs, so a caller that decrypts attacker-supplied ciphertext must not
-- pass the distinction on.
unpad
    :: HashAlgorithm hash
    => OAEPParams hash ByteString ByteString
    -- ^ OAEP params to use
    -> Int
    -- ^ size of public key in bytes
    -> ByteString
    -- ^ encoded message (not encrypted)
    -> Either Error ByteString
unpad oaep k em
    | paddingSuccess = Right msg
    | otherwise = Left MessageNotRecognized
  where
    -- parameters
    mgf = oaepMaskGenAlg oaep
    labelHash =
        B.convert $ hashWith (oaepHash oaep) (maybe B.empty id $ oaepLabel oaep)
            :: ByteString
    hashLen = hashDigestSize (oaepHash oaep)
    -- getting em's fields
    (pb, em0) = B.splitAt 1 em
    (maskedSeed, maskedDB) = B.splitAt hashLen em0
    seedMask = mgf maskedDB hashLen
    seed = B.pack $ B.zipWith xor maskedSeed seedMask
    dbmask = mgf seed (k - hashLen - 1)
    db = B.pack $ B.zipWith xor maskedDB dbmask
    -- getting db's fields
    (labelHash', db1) = B.splitAt hashLen db

    -- index of the first nonzero octet in db1, or its length when every octet
    -- is zero; all of them are looked at either way
    oneIndex =
        fst $
            foldl'
                step
                (fromIntegral (B.length db1) :: Word32, 1 :: Word32)
                (zip [0 ..] (B.unpack db1))
    step (idx, unseen) (i, b) = (select found i idx, unseen .&. complement found)
      where
        w = fromIntegral b :: Word32
        -- 0 when b is zero, 1 otherwise
        nonZero = (w .|. negate w) `shiftR` 31
        -- all ones at the first nonzero octet only
        found = negate (unseen .&. nonZero)
    select mask a b = (a .&. mask) .|. (b .&. complement mask)

    ps1 = B.take 1 $ B.drop (fromIntegral oneIndex) db1
    msg = B.drop (fromIntegral oneIndex + 1) db1

    paddingSuccess =
        and'
            [ labelHash' `B.constEq` labelHash
            , ps1 `B.constEq` B.replicate 1 0x1
            , pb `B.constEq` B.replicate 1 0x0
            ]
