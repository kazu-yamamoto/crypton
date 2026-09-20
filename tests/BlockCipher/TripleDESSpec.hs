{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module BlockCipher.TripleDESSpec (spec) where

import BlockCipher
import qualified Crypto.Cipher.DES as DES
import qualified Crypto.Cipher.TripleDES as TripleDES
import Crypto.Cipher.Types
import Crypto.Error (throwCryptoError)
import qualified Data.ByteString as B
import Imports

kats = defaultKATs

key1, key2, key3, message :: ByteString
key1 = "\x01\x23\x45\x67\x89\xab\xcd\xef"
key2 = "\xfe\xdc\xba\x98\x76\x54\x32\x10"
key3 = "\x13\x34\x57\x79\x9b\xbc\xdf\xf1"
message = "\x4e\x6f\x77\x20\x69\x73\x20\x74\x68\x65\x20\x74\x69\x6d\x65\x20"

des :: ByteString -> DES.DES
des k = throwCryptoError (cipherInit k)

cipher :: BlockCipher c => ByteString -> c
cipher k = throwCryptoError (cipherInit k)

-- | What the three stage constructions are, said in terms of DES itself: the
-- keys are used in the order and the directions their names describe, and
-- three stages under one key are the one stage the middle one undoes.
--
-- The suite had only round trips for these, which are equally happy with the
-- stages in the wrong order.
compositionTests :: Spec
compositionTests =
    describe "composition" $ do
        it "EEE3 is E,E,E under the three keys" $
            ecbEncrypt (cipher k123 :: TripleDES.DES_EEE3) message
                `shouldBe` e key3 (e key2 (e key1 message))
        it "EDE3 is E,D,E under the three keys" $
            ecbEncrypt (cipher k123 :: TripleDES.DES_EDE3) message
                `shouldBe` e key3 (d key2 (e key1 message))
        it "EEE2 is E,E,E with the first key again" $
            ecbEncrypt (cipher k12 :: TripleDES.DES_EEE2) message
                `shouldBe` e key1 (e key2 (e key1 message))
        it "EDE2 is E,D,E with the first key again" $
            ecbEncrypt (cipher k12 :: TripleDES.DES_EDE2) message
                `shouldBe` e key1 (d key2 (e key1 message))
        it "decryption undoes each of them" $ do
            back (cipher k123 :: TripleDES.DES_EEE3) `shouldBe` message
            back (cipher k123 :: TripleDES.DES_EDE3) `shouldBe` message
            back (cipher k12 :: TripleDES.DES_EEE2) `shouldBe` message
            back (cipher k12 :: TripleDES.DES_EDE2) `shouldBe` message
        it "EDE under one key repeated is DES" $ do
            ecbEncrypt (cipher (B.concat [key1, key1, key1]) :: TripleDES.DES_EDE3) message
                `shouldBe` e key1 message
            ecbEncrypt (cipher (B.concat [key1, key1]) :: TripleDES.DES_EDE2) message
                `shouldBe` e key1 message
  where
    k123 = B.concat [key1, key2, key3]
    k12 = B.concat [key1, key2]
    e k m = ecbEncrypt (des k) m
    d k m = ecbDecrypt (des k) m
    back c = ecbDecrypt c (ecbEncrypt c message)

spec :: Spec
spec = do
    modifyMaxSuccess (const 5) $
        testBlockCipher kats (undefined :: TripleDES.DES_EEE3)
    compositionTests
