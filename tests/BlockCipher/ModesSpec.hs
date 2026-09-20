{-# LANGUAGE OverloadedStrings #-}

module BlockCipher.ModesSpec (spec) where

import Crypto.Cipher.Camellia (Camellia128)
import Crypto.Cipher.DES (DES)
import Crypto.Cipher.Types
import Crypto.Error (throwCryptoError)
import Data.Bits (xor)
import qualified Data.ByteString as B
import Imports

-- | AES answers for its own modes in C; every other cipher reaches the generic
-- implementations in "Crypto.Cipher.Types.Block".  The suite checks that those
-- round trip, which a mode that chains the wrong way does too, and it checks
-- them only at the lengths QuickCheck happens to draw.
--
-- So write each mode out as its definition states it, and compare.
blocksOf :: Int -> ByteString -> [ByteString]
blocksOf n bs
    | B.null bs = []
    | otherwise = let (a, b) = B.splitAt n bs in a : blocksOf n b

bxor :: ByteString -> ByteString -> ByteString
bxor a b = B.pack (B.zipWith xor a b)

-- big-endian increment, which is what CTR counts with
incr :: ByteString -> ByteString
incr bs = B.pack (reverse (go (reverse (B.unpack bs))))
  where
    go [] = []
    go (w : ws)
        | w == 0xff = 0 : go ws
        | otherwise = (w + 1) : ws

refCBCEncrypt
    , refCBCDecrypt
    , refCFBEncrypt
    , refCFBDecrypt
    , refCTR
        :: BlockCipher c => c -> ByteString -> ByteString -> ByteString
refCBCEncrypt c iv msg = B.concat (go iv (blocksOf (blockSize c) msg))
  where
    go _ [] = []
    go v (m : ms) = let o = ecbEncrypt c (bxor v m) in o : go o ms
refCBCDecrypt c iv msg = B.concat (go iv (blocksOf (blockSize c) msg))
  where
    go _ [] = []
    go v (m : ms) = bxor v (ecbDecrypt c m) : go m ms
refCFBEncrypt c iv msg = B.concat (go iv (blocksOf (blockSize c) msg))
  where
    go _ [] = []
    go v (m : ms) = let o = bxor m (ecbEncrypt c v) in o : go o ms
refCFBDecrypt c iv msg = B.concat (go iv (blocksOf (blockSize c) msg))
  where
    go _ [] = []
    go v (m : ms) = bxor m (ecbEncrypt c v) : go m ms
refCTR c iv msg =
    B.concat
        (zipWith bxor (blocksOf (blockSize c) msg) (map (ecbEncrypt c) (iterate incr iv)))

modeTests :: BlockCipher c => String -> c -> ByteString -> Spec
modeTests name c iv0 =
    describe name $ do
        it "CBC encryption is what the definition says" $
            disagree (cbcEncrypt c iv) (refCBCEncrypt c iv0) wholeBlocks `shouldBe` []
        it "CBC decryption is what the definition says" $
            disagree (cbcDecrypt c iv) (refCBCDecrypt c iv0) wholeBlocks `shouldBe` []
        it "CFB encryption is what the definition says" $
            disagree (cfbEncrypt c iv) (refCFBEncrypt c iv0) wholeBlocks `shouldBe` []
        it "CFB decryption is what the definition says" $
            disagree (cfbDecrypt c iv) (refCFBDecrypt c iv0) wholeBlocks `shouldBe` []
        it "CTR is what the definition says, whole blocks or not" $
            disagree (ctrCombine c iv) (refCTR c iv0) everyLength `shouldBe` []
        it "and on a message of 64 KiB" $ do
            cbcEncrypt c iv big `shouldBe` refCBCEncrypt c iv0 big
            cbcDecrypt c iv big `shouldBe` refCBCDecrypt c iv0 big
            ctrCombine c iv big `shouldBe` refCTR c iv0 big
  where
    bsz = blockSize c
    iv = maybe (error "bad IV") id (makeIV iv0)
    -- the message, and the lengths to take of it
    message = B.concat (replicate 4 (B.pack (map fromIntegral [1 .. 255 :: Int])))
    wholeBlocks = [bsz * i | i <- [0 .. 20]]
    everyLength = [0 .. 40]
    big = B.concat (replicate 256 message)
    disagree lib ref lens =
        [n | n <- lens, let m = B.take n message, lib m /= ref m]

spec :: Spec
spec = do
    modeTests
        "DES"
        (throwCryptoError (cipherInit desKey) :: DES)
        (B.replicate 8 0x42)
    modeTests
        "Camellia128"
        (throwCryptoError (cipherInit camKey) :: Camellia128)
        (B.replicate 16 0x42)
  where
    desKey = "\x01\x23\x45\x67\x89\xab\xcd\xef" :: ByteString
    camKey =
        "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10" :: ByteString
