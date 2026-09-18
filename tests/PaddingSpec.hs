{-# LANGUAGE OverloadedStrings #-}

module PaddingSpec (spec) where

import Control.Exception (ErrorCall (..), evaluate)
import qualified Data.ByteString as B
import Data.List (isInfixOf)
import Imports

import Crypto.Data.Padding

cases =
    [ ("abcdef", 8, "abcdef\x02\x02")
    , ("abcd", 4, "abcd\x04\x04\x04\x04")
    , ("xyze", 5, "xyze\x01")
    ]

zeroCases =
    [ ("", 4, "\NUL\NUL\NUL\NUL", Nothing)
    , ("abcdef", 8, "abcdef\NUL\NUL", Nothing)
    , ("0123456789abcdef", 16, "0123456789abcdef", Just "0123456789abcdef")
    ]

-- instance Arbitrary where

testPad :: Int -> (B.ByteString, Int, B.ByteString) -> Spec
testPad n (inp, sz, padded) =
    it (show n) $
        propertyHoldCase
            [ eqTest "padded" padded (pad (PKCS7 sz) inp)
            , eqTest "unpadded" (Just inp) (unpad (PKCS7 sz) padded)
            ]

testZeroPad
    :: Int -> (B.ByteString, Int, B.ByteString, Maybe B.ByteString) -> Spec
testZeroPad n (inp, sz, padded, unpadded) =
    it (show n) $
        propertyHoldCase
            [ eqTest "padded" padded (pad (ZERO sz) inp)
            , eqTest "unpadded" unpadded (unpad (ZERO sz) padded)
            ]

-- | The padding octet of a PKCS7 block carries the number of octets added, so
-- it cannot describe a block longer than 255, and a block of zero has nothing
-- to describe.  Outside that range the octet is computed as an Int and then
-- narrowed to a Word8, which wraps: pad and unpad agree on the wrapped value
-- and hand back something that is not what was padded.
blockSizeTests :: Spec
blockSizeTests = describe "PKCS7 block size" $ do
    it "round trips at the smallest size" $
        unpad (PKCS7 1) (pad (PKCS7 1) msg) `shouldBe` Just msg
    it "round trips at the largest size" $
        unpad (PKCS7 255) (pad (PKCS7 255) msg) `shouldBe` Just msg
    it "refuses to pad with a block size above 255" $
        evaluate (B.length (pad (PKCS7 256) msg)) `shouldThrow` rangeError
    it "refuses to pad with a block size far above 255" $
        evaluate (B.length (pad (PKCS7 300) msg)) `shouldThrow` rangeError
    it "refuses to pad with a block size of zero" $
        evaluate (B.length (pad (PKCS7 0) msg)) `shouldThrow` rangeError
    it "refuses to pad with a negative block size" $
        evaluate (B.length (pad (PKCS7 (-1)) msg)) `shouldThrow` rangeError
    it "refuses to unpad with a block size outside the range" $
        mapM_
            (\sz -> unpad (PKCS7 sz) oversized `shouldBe` Nothing)
            [-1, 0, 256, 300]
  where
    msg = "a" :: B.ByteString
    -- what pad (PKCS7 300) produced while the octet was allowed to wrap
    oversized = msg `B.append` B.replicate 299 43
    rangeError (ErrorCall m) = "between 1 and 255" `isInfixOf` m

spec :: Spec
spec = do
    describe "Cases" $ zipWithM_ testPad [1 ..] cases
    describe "ZeroCases" $ zipWithM_ testZeroPad [1 ..] zeroCases
    blockSizeTests
