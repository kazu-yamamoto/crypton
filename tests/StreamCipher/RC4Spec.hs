{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module StreamCipher.RC4Spec where

import Control.Exception (evaluate)
import qualified Data.ByteString as B
import Test.Hspec

import qualified Crypto.Cipher.RC4 as RC4
import Data.ByteString (ByteString)
import Data.ByteString.Char8 ()

-- taken from wikipedia pages
vectors :: [(ByteString, ByteString, ByteString)]
vectors =
    [
        ( "Key"
        , "Plaintext"
        , "\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3"
        )
    ,
        ( "Wiki"
        , "pedia"
        , "\x10\x21\xBF\x04\x20"
        )
    ,
        ( "Secret"
        , "Attack at dawn"
        , "\x45\xA0\x1F\x64\x5F\xC3\x5B\x38\x35\x52\x54\x4B\x9B\xF5"
        )
    ]

spec :: Spec
spec = do
    sequence_ $ zipWith toKatTest is vectors
    -- the C reduced the key index modulo the key length, so dividing by zero
    it "refuses an empty key" $
        evaluate (RC4.initialize B.empty) `shouldThrow` anyErrorCall
    -- only the first 256 bytes are used
    it "ignores key bytes past 256" $
        snd (RC4.generate (RC4.initialize (long 0)) 64)
            `shouldBe` (snd (RC4.generate (RC4.initialize (long 1)) 64) :: ByteString)
  where
    long b = B.replicate 256 7 `B.append` B.replicate 100 b
    toKatTest i (key, plainText, cipherText) =
        it
            (show i)
            (snd (RC4.combine (RC4.initialize key) plainText) `shouldBe` cipherText)
    is :: [Int]
    is = [1 ..]
