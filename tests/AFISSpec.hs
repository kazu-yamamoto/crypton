{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}

module AFISSpec (spec) where

import Imports

import Control.Exception (evaluate)
import qualified Crypto.Data.AFIS as AFIS
import Crypto.Error
import Crypto.Hash
import Crypto.Random
import qualified Data.ByteString as B

mergeVec :: [(Int, SHA1, B.ByteString, B.ByteString)]
mergeVec =
    [
        ( 3
        , SHA1
        , "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
        , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\xd4\x76\xc8\x58\xbd\xf0\x15\xbe\x9f\x40\xe3\x65\x20\x1c\x9c\xb8\xd8\x1c\x16\x64"
        )
    ,
        ( 3
        , SHA1
        , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17"
        , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\xd6\x75\xc8\x59\xbb\xf7\x11\xbb\x95\x4b\xeb\x6c\x2e\x13\x90\xb5\xca\x0f\x06\x75\x17\x70\x39\x28"
        )
    ]

mergeKATs = zipWith toProp mergeVec [(0 :: Int) ..]
  where
    toProp (nbExpands, hashAlg, expected, dat) i =
        it ("merge " ++ show i) (AFIS.merge hashAlg nbExpands dat `shouldBe` expected)

data AFISParams = AFISParams B.ByteString Int SHA1 ChaChaDRG

instance Show AFISParams where
    show (AFISParams dat expand _ _) = "data: " ++ show dat ++ " expanded: " ++ show expand

instance Arbitrary AFISParams where
    arbitrary =
        AFISParams
            <$> arbitraryBSof 3 46
            <*> choose (2, 2)
            <*> elements [SHA1]
            <*> arbitrary

instance Arbitrary ChaChaDRG where
    arbitrary = drgNewTest <$> arbitrary

-- | Parameters neither function can work with.  An expand count of zero used
-- to divide by zero in merge, a negative one reported the data as null, and an
-- expand count of one was accepted and handed the diffused data straight back
-- as though it were the secret -- which is the one that does not announce
-- itself.  split already refused all three, so it had nothing to say about a
-- secret of no bytes, which it split into nothing that merge then refused.
invalidParameterTests :: Spec
invalidParameterTests =
    describe "invalid parameters" $ do
        it "merge refuses an expand count of zero" $
            evaluate (tryMerge 0 diffused) `shouldThrow` refused
        it "merge refuses a negative expand count" $
            evaluate (tryMerge (-1) diffused) `shouldThrow` refused
        it "merge refuses an expand count of one" $
            evaluate (tryMerge 1 diffused) `shouldThrow` refused
        it "merge refuses data that is not a multiple of the expand count" $
            evaluate (tryMerge 3 diffused) `shouldThrow` refused
        it "merge refuses empty data" $
            evaluate (tryMerge 4 B.empty) `shouldThrow` refused
        it "split refuses an expand count below two" $ do
            evaluate (trySplit 0 secret) `shouldThrow` refused
            evaluate (trySplit 1 secret) `shouldThrow` refused
            evaluate (trySplit (-1) secret) `shouldThrow` refused
        it "split refuses an empty secret" $
            evaluate (trySplit 4 B.empty) `shouldThrow` refused
        it "the recoverable variants report instead of raising" $ do
            AFIS.tryMerge SHA1 0 diffused `shouldBe` failed
            AFIS.tryMerge SHA1 1 diffused `shouldBe` failed
            AFIS.tryMerge SHA1 3 diffused `shouldBe` failed
            AFIS.tryMerge SHA1 4 B.empty `shouldBe` failed
            fmap fst (AFIS.trySplit SHA1 rng 1 secret) `shouldBe` failed
            fmap fst (AFIS.trySplit SHA1 rng 4 B.empty) `shouldBe` failed
        it "the recoverable variants still split and merge" $ do
            let d = fmap fst (AFIS.trySplit SHA1 rng 4 secret)
            d `shouldBe` CryptoPassed diffused
            (d >>= AFIS.tryMerge SHA1 4) `shouldBe` CryptoPassed secret
        it "a good split still merges back" $
            AFIS.merge SHA1 4 diffused `shouldBe` secret
  where
    rng = drgNewTest (1, 2, 3, 4, 5)
    secret = "0123456789abcdef0123" :: B.ByteString
    diffused = fst (AFIS.split SHA1 rng 4 secret) :: B.ByteString
    tryMerge e d = AFIS.merge SHA1 e d :: B.ByteString
    trySplit e d = fst (AFIS.split SHA1 rng e d) :: B.ByteString
    failed = CryptoFailed CryptoError_ParameterInvalid :: CryptoFailable B.ByteString
    refused e = e == CryptoError_ParameterInvalid

spec :: Spec
spec = do
    describe "KAT merge" $ sequence_ mergeKATs
    invalidParameterTests
    prop "merge.split == id" $ \(AFISParams bs e hf rng) -> bs == (AFIS.merge hf e $ fst (AFIS.split hf rng e bs))
