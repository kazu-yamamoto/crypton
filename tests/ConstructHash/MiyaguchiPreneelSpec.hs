module ConstructHash.MiyaguchiPreneelSpec (spec) where

import Crypto.Cipher.AES (AES128)
import Crypto.ConstructHash.MiyaguchiPreneel as MiyaguchiPreneel

import Imports

import qualified Data.ByteArray as B
import Data.ByteArray.Encoding (Base (Base16), convertFromBase)
import qualified Data.ByteString.Char8 as B8

runMP128 :: ByteString -> ByteString
runMP128 s = B.convert (MiyaguchiPreneel.compute s :: MiyaguchiPreneel AES128)

hxs :: String -> ByteString
hxs =
    either (error . ("hxs:" ++)) id
        . convertFromBase Base16
        . B8.pack
        . filter (/= ' ')

-- | Values from pycryptodome's AES, chained by hand with 0x80 padding.
gAES128 :: Spec
gAES128 =
    igroup
        "aes128"
        [ runMP128 B8.empty
            `shouldBe` hxs "bad78e72 6c1ec02b 7ebfe92b 23d9ec34"
        , runMP128 (hxs "01000000 00000000 00000000 00000000")
            `shouldBe` hxs "ef161f2b d4ce9bcd 8a771570 a8fa51c9"
        , runMP128 (hxs "00000000 00000000 00000000 00000001")
            `shouldBe` hxs "a7206541 44a17514 cdb1a563 05420a8c"
        , runMP128
            ( hxs $
                "00000000 00000000 00000000 00000000"
                    ++ "01"
            )
            `shouldBe` hxs "fc2553f0 50b5fcdb 1bc589ce 811a7b43"
        , runMP128 (hxs "00000000 00000000 00000000 000000")
            `shouldBe` hxs "ff49b8df 4a97cbe0 3833e661 97620d2d"
        , runMP128 (B8.pack "a")
            `shouldBe` hxs "f4899ebc 761071fe fe85dcc2 4354711e"
        ]

-- | Zero padding made these pairs collide.
collisions :: Spec
collisions =
    describe "trailing zeros" $ do
        it "\"a\" and \"a\\0\" differ" $
            runMP128 (B8.pack "a") `shouldNotBe` runMP128 (B8.pack "a\0")
        it "empty and a zero block differ" $
            runMP128 B8.empty `shouldNotBe` runMP128 (B.replicate 16 0)

igroup :: String -> [Expectation] -> Spec
igroup nm = describe nm . sequence_ . zipWith (flip ($)) [1 ..] . map icase
  where
    icase c i = it (show (i :: Int)) c

vectors :: Spec
vectors =
    describe "KATs" $ do
        gAES128

spec :: Spec
spec = do
    vectors
    collisions
