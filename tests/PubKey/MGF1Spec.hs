{-# LANGUAGE OverloadedStrings #-}

module PubKey.MGF1Spec (spec) where

import Control.Monad (zipWithM_)
import Test.Hspec

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Crypto.Hash
import qualified Data.ByteArray as BA
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.PubKey.MaskGenFunction
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (choose, forAll)

import Utils

data VectorMgf = VectorMgf
    { seed :: ByteString
    , dbMask :: ByteString
    }

doMGFTest i vmgf = it (show i) (actual `shouldBe` dbMask vmgf)
  where
    actual = mgf1 SHA1 (seed vmgf) (B.length $ dbMask vmgf)

vectorsMGF =
    [ VectorMgf
        { seed =
            "\xdf\x1a\x89\x6f\x9d\x8b\xc8\x16\xd9\x7c\xd7\xa2\xc4\x3b\xad\x54\x6f\xbe\x8c\xfe"
        , dbMask =
            "\x66\xe4\x67\x2e\x83\x6a\xd1\x21\xba\x24\x4b\xed\x65\x76\xb8\x67\xd9\xa4\x47\xc2\x8a\x6e\x66\xa5\xb8\x7d\xee\x7f\xbc\x7e\x65\xaf\x50\x57\xf8\x6f\xae\x89\x84\xd9\xba\x7f\x96\x9a\xd6\xfe\x02\xa4\xd7\x5f\x74\x45\xfe\xfd\xd8\x5b\x6d\x3a\x47\x7c\x28\xd2\x4b\xa1\xe3\x75\x6f\x79\x2d\xd1\xdc\xe8\xca\x94\x44\x0e\xcb\x52\x79\xec\xd3\x18\x3a\x31\x1f\xc8\x97\x39\xa9\x66\x43\x13\x6e\x8b\x0f\x46\x5e\x87\xa4\x53\x5c\xd4\xc5\x9b\x10\x02\x8d"
        }
    ]

-- | RFC 8017's definition through the pure hash API, block by block, which
-- shares nothing with mgf1's in-place contexts or with the one-shot hash.
reference :: HashAlgorithm a => a -> ByteString -> Int -> ByteString
reference alg sd len = B.take len $ B.concat [block c | c <- [0 .. blocks - 1]]
  where
    blocks = (len + hashDigestSize alg - 1) `div` hashDigestSize alg
    block c = BA.convert (hashFinalize (hashUpdates (hashInitWith alg) [sd, i2ospOf_ 4 (fromIntegral c)])) :: ByteString

spec :: Spec
spec = do
    zipWithM_ doMGFTest [katZero ..] vectorsMGF
    describe "against the definition" $
        mapM_ agree
            [ ("SHA1", \s n -> (mgf1 SHA1 s n, reference SHA1 s n))
            , ("SHA256", \s n -> (mgf1 SHA256 s n, reference SHA256 s n))
            , ("SHA512", \s n -> (mgf1 SHA512 s n, reference SHA512 s n))
            , ("SHA3_256", \s n -> (mgf1 SHA3_256 s n, reference SHA3_256 s n))
            , ("Blake2b_512", \s n -> (mgf1 Blake2b_512 s n, reference Blake2b_512 s n))
            ]
  where
    agree (name, f) = prop name $
        forAll (arbitraryBSof 0 100) $ \s -> forAll (choose (0, 300)) $ \n ->
            let (got, want) = f s n in got == (want :: ByteString)
