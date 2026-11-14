{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.ConstructHash.MiyaguchiPreneel
-- License     : BSD-style
-- Maintainer  : Kei Hibino <ex8k.hibino@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Provide the hash function construction method from block cipher
-- <https://en.wikipedia.org/wiki/One-way_compression_function>
module Crypto.ConstructHash.MiyaguchiPreneel (
    compute,
    compute',
    MiyaguchiPreneel,
) where

import qualified Data.List as L

import Crypto.Cipher.Types
import Crypto.Cipher.Types.Utils (chunk)
import Crypto.Error (throwCryptoError)
import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B

newtype MiyaguchiPreneel a = MP Bytes
    deriving (ByteArrayAccess)

instance Eq (MiyaguchiPreneel a) where
    MP b1 == MP b2 = B.constEq b1 b2

-- | Compute Miyaguchi-Preneel one way compress using the supplied block cipher.
--
-- The message is padded with 0x80 and then zeros to a whole number of blocks
-- (ISO/IEC 9797-1 method 2).  Before 2.3 it was padded with zeros only, so
-- messages differing in trailing zeros, such as @\"a\"@ and @\"a\\0\"@,
-- gave the same output.
compute'
    :: (ByteArrayAccess bin, BlockCipher cipher)
    => (Bytes -> cipher)
    -- ^ key build function to compute Miyaguchi-Preneel. care about block-size and key-size
    -> bin
    -- ^ input message
    -> MiyaguchiPreneel cipher
    -- ^ output tag
compute' g =
    MP . L.foldl' (step $ g) (B.replicate bsz 0) . chunk bsz . pad . B.convert
  where
    bsz = blockSize (g B.empty {- dummy to get block size -})
    pad :: Bytes -> Bytes
    pad msg = B.concat [msg, B.singleton 0x80, B.replicate (zeros msg) 0]
    zeros msg = negate (B.length msg + 1) `mod` bsz

-- | Compute Miyaguchi-Preneel one way compress using the inferred block cipher.
--   Only safe when KEY-SIZE equals to BLOCK-SIZE.
--
--   Simple usage /mp' msg :: MiyaguchiPreneel AES128/
compute
    :: (ByteArrayAccess bin, BlockCipher cipher)
    => bin
    -- ^ input message
    -> MiyaguchiPreneel cipher
    -- ^ output tag
compute = compute' $ throwCryptoError . cipherInit

-- | computation step of Miyaguchi-Preneel
step
    :: (ByteArray ba, BlockCipher k)
    => (ba -> k)
    -> ba
    -> ba
    -> ba
step g iv msg =
    ecbEncrypt k msg `bxor` iv `bxor` msg
  where
    k = g iv

bxor :: ByteArray ba => ba -> ba -> ba
bxor = B.bxor
