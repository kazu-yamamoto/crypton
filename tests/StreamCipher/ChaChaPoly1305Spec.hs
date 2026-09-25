{-# LANGUAGE OverloadedStrings #-}

module StreamCipher.ChaChaPoly1305Spec where

import qualified Crypto.Cipher.ChaCha.Poly1305 as One
import qualified Crypto.Cipher.ChaChaPoly1305 as CP
import Crypto.Cipher.Types
import Crypto.Error
import Imports
import MAC.Poly1305Spec ()

import Data.Bits (xor)
import qualified Data.ByteArray as B (convert)
import qualified Data.ByteString as B

plaintext
    , aad
    , key
    , iv
    , ivX
    , ciphertext
    , ciphertextX
    , tag
    , tagX
    , nonce1
    , nonce2
    , nonce3
    , nonce4
    , nonce5
    , nonce6
    , nonce7
    , nonce8
    , nonce9
    , nonce10
        :: B.ByteString
plaintext =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
aad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
key =
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
iv = "\x40\x41\x42\x43\x44\x45\x46\x47"
ivX = B.pack [0x40 .. 0x57]
constant = "\x07\x00\x00\x00"
ciphertext =
    "\xd3\x1a\x8d\x34\x64\x8e\x60\xdb\x7b\x86\xaf\xbc\x53\xef\x7e\xc2\xa4\xad\xed\x51\x29\x6e\x08\xfe\xa9\xe2\xb5\xa7\x36\xee\x62\xd6\x3d\xbe\xa4\x5e\x8c\xa9\x67\x12\x82\xfa\xfb\x69\xda\x92\x72\x8b\x1a\x71\xde\x0a\x9e\x06\x0b\x29\x05\xd6\xa5\xb6\x7e\xcd\x3b\x36\x92\xdd\xbd\x7f\x2d\x77\x8b\x8c\x98\x03\xae\xe3\x28\x09\x1b\x58\xfa\xb3\x24\xe4\xfa\xd6\x75\x94\x55\x85\x80\x8b\x48\x31\xd7\xbc\x3f\xf4\xde\xf0\x8e\x4b\x7a\x9d\xe5\x76\xd2\x65\x86\xce\xc6\x4b\x61\x16"
ciphertextX =
    "\xbd\x6d\x17\x9d\x3e\x83\xd4\x3b\x95\x76\x57\x94\x93\xc0\xe9\x39\x57\x2a\x17\x00\x25\x2b\xfa\xcc\xbe\xd2\x90\x2c\x21\x39\x6c\xbb\x73\x1c\x7f\x1b\x0b\x4a\xa6\x44\x0b\xf3\xa8\x2f\x4e\xda\x7e\x39\xae\x64\xc6\x70\x8c\x54\xc2\x16\xcb\x96\xb7\x2e\x12\x13\xb4\x52\x2f\x8c\x9b\xa4\x0d\xb5\xd9\x45\xb1\x1b\x69\xb9\x82\xc1\xbb\x9e\x3f\x3f\xac\x2b\xc3\x69\x48\x8f\x76\xb2\x38\x35\x65\xd3\xff\xf9\x21\xf9\x66\x4c\x97\x63\x7d\xa9\x76\x88\x12\xf6\x15\xc6\x8b\x13\xb5\x2e"
tag = "\x1a\xe1\x0b\x59\x4f\x09\xe2\x6a\x7e\x90\x2e\xcb\xd0\x60\x06\x91"
tagX = "\xc0\x87\x59\x24\xc1\xc7\x98\x79\x47\xde\xaf\xd8\x78\x0a\xcf\x49"
nonce1 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce2 = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce3 = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce4 = "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce5 = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
nonce6 = "\x00\x00\x00\x00\x00\x00\x00\x00"
nonce7 = "\x01\x00\x00\x00\x00\x00\x00\x00"
nonce8 = "\xff\x00\x00\x00\x00\x00\x00\x00"
nonce9 = "\x00\x01\x00\x00\x00\x00\x00\x00"
nonce10 = "\xff\xff\xff\xff\xff\xff\xff\xff"

a5key :: ByteString
a5key =
    "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0"

a5nonce :: ByteString
a5nonce = "\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08"

a5aad :: ByteString
a5aad = "\xf3\x33\x88\x86\x00\x00\x00\x00\x00\x00\x4e\x91"

a5cipher :: ByteString
a5cipher =
    "\x64\xa0\x86\x15\x75\x86\x1a\xf4\x60\xf0\x62\xc7\x9b\xe6\x43\xbd\x5e\x80\x5c\xfd\x34\x5c\xf3\x89\xf1\x08\x67\x0a\xc7\x6c\x8c\xb2\x4c\x6c\xfc\x18\x75\x5d\x43\xee\xa0\x9e\xe9\x4e\x38\x2d\x26\xb0\xbd\xb7\xb7\x3c\x32\x1b\x01\x00\xd4\xf0\x3b\x7f\x35\x58\x94\xcf\x33\x2f\x83\x0e\x71\x0b\x97\xce\x98\xc8\xa8\x4a\xbd\x0b\x94\x81\x14\xad\x17\x6e\x00\x8d\x33\xbd\x60\xf9\x82\xb1\xff\x37\xc8\x55\x97\x97\xa0\x6e\xf4\xf0\xef\x61\xc1\x86\x32\x4e\x2b\x35\x06\x38\x36\x06\x90\x7b\x6a\x7c\x02\xb0\xf9\xf6\x15\x7b\x53\xc8\x67\xe4\xb9\x16\x6c\x76\x7b\x80\x4d\x46\xa5\x9b\x52\x16\xcd\xe7\xa4\xe9\x90\x40\xc5\xa4\x04\x33\x22\x5e\xe2\x82\xa1\xb0\xa0\x6c\x52\x3e\xaf\x45\x34\xd7\xf8\x3f\xa1\x15\x5b\x00\x47\x71\x8c\xbc\x54\x6a\x0d\x07\x2b\x04\xb3\x56\x4e\xea\x1b\x42\x22\x73\xf5\x48\x27\x1a\x0b\xb2\x31\x60\x53\xfa\x76\x99\x19\x55\xeb\xd6\x31\x59\x43\x4e\xce\xbb\x4e\x46\x6d\xae\x5a\x10\x73\xa6\x72\x76\x27\x09\x7a\x10\x49\xe6\x17\xd9\x1d\x36\x10\x94\xfa\x68\xf0\xff\x77\x98\x71\x30\x30\x5b\xea\xba\x2e\xda\x04\xdf\x99\x7b\x71\x4d\x6c\x6f\x2c\x29\xa6\xad\x5c\xb4\x02\x2b\x02\x70\x9b"

a5plain :: ByteString
a5plain =
    "\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x73\x20\x61\x72\x65\x20\x64\x72\x61\x66\x74\x20\x64\x6f\x63\x75\x6d\x65\x6e\x74\x73\x20\x76\x61\x6c\x69\x64\x20\x66\x6f\x72\x20\x61\x20\x6d\x61\x78\x69\x6d\x75\x6d\x20\x6f\x66\x20\x73\x69\x78\x20\x6d\x6f\x6e\x74\x68\x73\x20\x61\x6e\x64\x20\x6d\x61\x79\x20\x62\x65\x20\x75\x70\x64\x61\x74\x65\x64\x2c\x20\x72\x65\x70\x6c\x61\x63\x65\x64\x2c\x20\x6f\x72\x20\x6f\x62\x73\x6f\x6c\x65\x74\x65\x64\x20\x62\x79\x20\x6f\x74\x68\x65\x72\x20\x64\x6f\x63\x75\x6d\x65\x6e\x74\x73\x20\x61\x74\x20\x61\x6e\x79\x20\x74\x69\x6d\x65\x2e\x20\x49\x74\x20\x69\x73\x20\x69\x6e\x61\x70\x70\x72\x6f\x70\x72\x69\x61\x74\x65\x20\x74\x6f\x20\x75\x73\x65\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x73\x20\x61\x73\x20\x72\x65\x66\x65\x72\x65\x6e\x63\x65\x20\x6d\x61\x74\x65\x72\x69\x61\x6c\x20\x6f\x72\x20\x74\x6f\x20\x63\x69\x74\x65\x20\x74\x68\x65\x6d\x20\x6f\x74\x68\x65\x72\x20\x74\x68\x61\x6e\x20\x61\x73\x20\x2f\xe2\x80\x9c\x77\x6f\x72\x6b\x20\x69\x6e\x20\x70\x72\x6f\x67\x72\x65\x73\x73\x2e\x2f\xe2\x80\x9d"

a5tag :: ByteString
a5tag = "\xee\xad\x9d\x67\x89\x0c\xbb\x22\x39\x23\x36\xfe\xa1\x85\x1f\x38"

rfc8439encrypt = ct `shouldBe` a5cipher
  where
    ct = case CP.aeadChacha20poly1305Init a5key a5nonce of
        CryptoPassed st -> snd $ aeadSimpleEncrypt st a5aad a5plain 16
        _ -> "dummy"

rfc8439decrypt = mpt `shouldBe` Just a5plain
  where
    mpt = case CP.aeadChacha20poly1305Init a5key a5nonce of
        CryptoPassed st -> aeadSimpleDecrypt st a5aad a5cipher (AuthTag $ B.convert a5tag)
        _ -> Nothing

-- | The key is checked once, where it is made, and initializing cannot fail
-- after that.
keyTests :: Spec
keyTests = describe "key" $ do
    it "takes thirty-two bytes" $
        passed (CP.key (B.replicate 32 0x41)) `shouldBe` True
    it "refuses any other length" $
        [n | n <- [0, 1, 16, 31, 33, 64], passed (CP.key (B.replicate n 0x41))]
            `shouldBe` []
    it "says which error" $
        -- Key has no Show, on purpose: it is key material
        errorOf (CP.key (B.replicate 31 0x41))
            `shouldBe` Just CryptoError_KeySizeInvalid
    it "and the AEAD entry point reports the same thing" $
        errorOf
            (CP.aeadChacha20poly1305Init (B.replicate 31 0x41) (B.replicate 12 0x42))
            `shouldBe` Just CryptoError_KeySizeInvalid
    it "a key that was taken initializes without an error case" $ do
        let k = throwCryptoError (CP.key (B.replicate 32 0x41))
            n = throwCryptoError (CP.nonce12 (B.replicate 12 0x42))
            st = CP.initialize k n
            (out, st') = CP.encrypt ("hello" :: B.ByteString) (CP.finalizeAAD st)
        B.length out `shouldBe` 5
        B.length (B.convert (CP.finalize st') :: B.ByteString) `shouldBe` 16
  where
    passed (CryptoPassed _) = True
    passed (CryptoFailed _) = False
    errorOf (CryptoFailed e) = Just e
    errorOf (CryptoPassed _) = Nothing

spec :: Spec
spec = do
    keyTests
    it "V1" runEncrypt
    it "V1-decrypt" runDecrypt
    it "V1-extended" runEncryptX
    it "V1-extended-decrypt" runDecryptX
    it "nonce increment" runNonceInc
    it "RFC8439 A5 enc" rfc8439encrypt
    it "RFC8439 A5 dec" rfc8439decrypt
    oneShotTests
  where
    runEncrypt =
        let ini =
                CP.initialize
                    (throwCryptoError $ CP.key key)
                    (throwCryptoError $ CP.nonce8 constant iv)
            afterAAD = CP.finalizeAAD (CP.appendAAD aad ini)
            (out, afterEncrypt) = CP.encrypt plaintext afterAAD
            outtag = CP.finalize afterEncrypt
         in propertyHoldCase
                [ eqTest "ciphertext" ciphertext out
                , eqTest "tag" tag (B.convert outtag)
                ]
    runEncryptX =
        let ini =
                CP.initializeX
                    (throwCryptoError $ CP.key key)
                    (throwCryptoError $ CP.nonce24 ivX)
            afterAAD = CP.finalizeAAD (CP.appendAAD aad ini)
            (out, afterEncrypt) = CP.encrypt plaintext afterAAD
            outtag = CP.finalize afterEncrypt
         in propertyHoldCase
                [ eqTest "ciphertext" ciphertextX out
                , eqTest "tag" tagX (B.convert outtag)
                ]

    runDecrypt =
        let ini =
                CP.initialize
                    (throwCryptoError $ CP.key key)
                    (throwCryptoError $ CP.nonce8 constant iv)
            afterAAD = CP.finalizeAAD (CP.appendAAD aad ini)
            (out, afterDecrypt) = CP.decrypt ciphertext afterAAD
            outtag = CP.finalize afterDecrypt
         in propertyHoldCase
                [ eqTest "plaintext" plaintext out
                , eqTest "tag" tag (B.convert outtag)
                ]

    runDecryptX =
        let ini =
                CP.initializeX
                    (throwCryptoError $ CP.key key)
                    (throwCryptoError $ CP.nonce24 ivX)
            afterAAD = CP.finalizeAAD (CP.appendAAD aad ini)
            (out, afterDecrypt) = CP.decrypt ciphertextX afterAAD
            outtag = CP.finalize afterDecrypt
         in propertyHoldCase
                [ eqTest "plaintext" plaintext out
                , eqTest "tag" tagX (B.convert outtag)
                ]

    runNonceInc =
        let n1 = throwCryptoError . CP.nonce12 $ nonce1
            n3 = throwCryptoError . CP.nonce12 $ nonce3
            n5 = throwCryptoError . CP.nonce12 $ nonce5
            n6 = throwCryptoError . CP.nonce8 constant $ nonce6
            n8 = throwCryptoError . CP.nonce8 constant $ nonce8
            n10 = throwCryptoError . CP.nonce8 constant $ nonce10
         in propertyHoldCase
                [ eqTest "nonce12a" nonce2 $ B.convert . CP.incrementNonce $ n1
                , eqTest "nonce12b" nonce4 $ B.convert . CP.incrementNonce $ n3
                , eqTest "nonce12c" nonce1 $ B.convert . CP.incrementNonce $ n5
                , eqTest "nonce8a" (B.concat [constant, nonce7]) $
                    B.convert . CP.incrementNonce $
                        n6
                , eqTest "nonce8b" (B.concat [constant, nonce9]) $
                    B.convert . CP.incrementNonce $
                        n8
                , eqTest "nonce8c" (B.concat [constant, nonce6]) $
                    B.convert . CP.incrementNonce $
                        n10
                ]

-- | Crypto.Cipher.ChaCha.Poly1305 does a whole message in one call where
-- Crypto.Cipher.ChaChaPoly1305 does it in steps.  It has to answer exactly
-- what the steps answer, and what RFC 8439 prints.
oneShotTests :: Spec
oneShotTests = describe "Crypto.Cipher.ChaCha.Poly1305" $ do
    it "RFC 8439 2.8.2, twelve-byte nonce" $
        propertyHoldCase
            [ eqTest "ciphertext" ciphertext (B.take (B.length ciphertext) sealed)
            , eqTest "tag" tag (B.drop (B.length ciphertext) sealed)
            ]
    it "decrypt undoes encrypt" $
        One.decrypt ctx nonce12 aad sealed 16 `shouldBe` Just plaintext
    it "refuses a flipped bit in the ciphertext" $
        One.decrypt ctx nonce12 aad (flipHead sealed) 16
            `shouldBe` (Nothing :: Maybe B.ByteString)
    it "refuses a flipped bit in the tag" $
        One.decrypt ctx nonce12 aad (flipLast sealed) 16
            `shouldBe` (Nothing :: Maybe B.ByteString)
    it "refuses input shorter than the tag" $
        One.decrypt ctx nonce12 aad (B.replicate 8 0) 16
            `shouldBe` (Nothing :: Maybe B.ByteString)
    it "refuses a nonce that is not twelve bytes" $ do
        One.decrypt ctx (B.replicate 10 0) aad sealed 16
            `shouldBe` (Nothing :: Maybe B.ByteString)
        -- eight is the other ChaCha construction, not this AEAD
        One.decrypt ctx (B.replicate 8 0) aad sealed 16
            `shouldBe` (Nothing :: Maybe B.ByteString)
    it "decryptWithTag hands back the tag encrypt made" $
        case One.decryptWithTag ctx nonce12 aad (B.take (B.length ciphertext) sealed) 16 of
            CryptoFailed e -> expectationFailure (show e)
            CryptoPassed (body, t) ->
                propertyHoldCase
                    [ eqTest "plaintext" plaintext body
                    , eqTest "tag" (AuthTag (B.convert tag)) t
                    ]
    it "agrees with the step-at-a-time interface over a different message" $
        let msg = "another message, of a length that is not a multiple of 16" :: B.ByteString
            ad = "\x01\x02\x03" :: B.ByteString
            ini = CP.initialize (throwCryptoError $ CP.key key)
                                (throwCryptoError $ CP.nonce12 nonce12)
            afterAAD = CP.finalizeAAD (CP.appendAAD ad ini)
            (out, afterEnc) = CP.encrypt msg afterAAD
            t = CP.finalize afterEnc
            one = throwCryptoError (One.encrypt ctx nonce12 ad msg 16) :: B.ByteString
         in propertyHoldCase
                [ eqTest "ciphertext" out (B.take (B.length out) one)
                , eqTest "tag" (B.convert t :: B.ByteString) (B.drop (B.length out) one)
                ]
  where
    ctx = throwCryptoError (One.newContext key)
    -- the same nonce the step interface builds from constant and iv
    nonce12 = constant `B.append` iv
    sealed = throwCryptoError (One.encrypt ctx nonce12 aad plaintext 16) :: B.ByteString
    flipHead bs = B.cons (B.head bs `xor` 1) (B.tail bs)
    flipLast bs =
        B.snoc (B.init bs) (B.last bs `xor` 1)
