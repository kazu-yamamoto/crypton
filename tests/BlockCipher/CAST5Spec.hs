{-# LANGUAGE OverloadedStrings #-}

module BlockCipher.CAST5Spec (spec) where

import BlockCipher
import Imports

import Control.Exception (evaluate)
import qualified Crypto.Cipher.CAST5 as CAST5
import Crypto.Cipher.Types
import Crypto.Error (throwCryptoError)
import qualified Data.ByteString as B

vectors_ecb =
    -- key plaintext ciphertext
    [ KAT_ECB
        "\x01\x23\x45\x67\x12\x34\x56\x78\x23\x45\x67\x89\x34\x56\x78\x9A"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\x23\x8B\x4F\xE5\x84\x7E\x44\xB2"
    , KAT_ECB
        "\x01\x23\x45\x67\x12\x34\x56\x78\x23\x45"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\xEB\x6A\x71\x1A\x2C\x02\x27\x1B"
    , KAT_ECB
        "\x01\x23\x45\x67\x12"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\x7A\xC8\x16\xD1\x6E\x9B\x30\x2E"
    ]

kats = defaultKATs{kat_ECB = vectors_ecb}

spec :: Spec
spec = do
    testBlockCipher kats (undefined :: CAST5.CAST5)
    describe "CAST5 ECB" $ do
        -- the short block used to come back as uninitialised memory
        it "refuses to encrypt a message that is not whole blocks" $
            evaluate (B.length (ecbEncrypt ctx (B.replicate 12 0)))
                `shouldThrow` anyErrorCall
        it "refuses to decrypt a message that is not whole blocks" $
            evaluate (B.length (ecbDecrypt ctx (B.replicate 12 0)))
                `shouldThrow` anyErrorCall
  where
    ctx = throwCryptoError (cipherInit (B.replicate 16 0x2b)) :: CAST5.CAST5
