{-# LANGUAGE OverloadedStrings #-}

module PubKey.ElGamalSpec (spec) where

import Crypto.Error
import Crypto.Hash (SHA256 (..))
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.ElGamal as ElGamal
import Crypto.Random (drgNewTest, withDRG)

import Imports

-- | The 1024-bit MODP group of RFC 2409 section 6.2, whose generator is 2.
p :: Integer
p =
    0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

params :: DH.Params
params = DH.Params p 2 1024

priv :: DH.PrivateNumber
priv = DH.PrivateNumber 0x1f3b5d79a2c4e60813579bdf2468ace0

pub :: DH.PublicNumber
pub = ElGamal.generatePublic params priv

message :: Integer
message = 0x48656c6c6f2c20456c47616d616c21

-- | A usable ephemeral value: within [1, p-2] and not reused elsewhere here.
ephemeral :: ElGamal.EphemeralKey
ephemeral = ElGamal.EphemeralKey 0x2c4e60813579bdf2468ace01f3b5d79a

encryptionTests :: Spec
encryptionTests = describe "encryption" $ do
    it "decrypts what it encrypts" $
        (ElGamal.encryptWith ephemeral params pub message >>= ElGamal.decrypt params priv)
            `shouldBe` CryptoPassed message
    it "refuses an ephemeral value of zero" $
        -- it would leave c2 equal to the message
        ElGamal.encryptWith (ElGamal.EphemeralKey 0) params pub message
            `shouldBe` CryptoFailed CryptoError_ParameterInvalid
    it "refuses an ephemeral value at or above p-1" $
        ElGamal.encryptWith (ElGamal.EphemeralKey (p - 1)) params pub message
            `shouldBe` CryptoFailed CryptoError_ParameterInvalid
    it "refuses a peer public number generating a tiny subgroup" $
        mapM_
            ( \h ->
                ElGamal.encryptWith ephemeral params (DH.PublicNumber h) message
                    `shouldBe` CryptoFailed CryptoError_ParameterInvalid
            )
            [0, 1, p - 1, p]
    it "refuses a message at or above the modulus" $
        -- it would come back reduced
        ElGamal.encryptWith ephemeral params pub p
            `shouldBe` CryptoFailed CryptoError_ParameterInvalid
    it "refuses a negative message" $
        ElGamal.encryptWith ephemeral params pub (-1)
            `shouldBe` CryptoFailed CryptoError_ParameterInvalid

decryptionTests :: Spec
decryptionTests = describe "decryption" $ do
    it "refuses a first component of zero rather than raising" $
        -- zero has no inverse modulo p
        ElGamal.decrypt params priv (0, 1)
            `shouldBe` CryptoFailed CryptoError_ParameterInvalid
    it "refuses a first component at or above the modulus" $
        ElGamal.decrypt params priv (p, 1)
            `shouldBe` CryptoFailed CryptoError_ParameterInvalid
    it "refuses a second component out of range" $
        ElGamal.decrypt params priv (2, p)
            `shouldBe` CryptoFailed CryptoError_ParameterInvalid

signatureTests :: Spec
signatureTests = describe "signature" $ do
    it "verifies what it signs" $
        case ElGamal.signWith k params priv SHA256 msg of
            Nothing -> expectationFailure "expected a signature"
            Just sig -> ElGamal.verify params pub SHA256 msg sig `shouldBe` True
    it "refuses a k of zero" $
        ElGamal.signWith 0 params priv SHA256 msg `shouldBe` Nothing
    it "refuses a negative k" $
        ElGamal.signWith (-1) params priv SHA256 msg `shouldBe` Nothing
    it "refuses a k at or above p-1" $
        mapM_
            (\k' -> ElGamal.signWith k' params priv SHA256 msg `shouldBe` Nothing)
            [p - 1, p, p + 1]
    it "accepts the largest usable k" $
        -- p-2 and p-1 are consecutive, so they are coprime
        case ElGamal.signWith (p - 2) params priv SHA256 msg of
            Nothing -> expectationFailure "expected a signature"
            Just sig -> ElGamal.verify params pub SHA256 msg sig `shouldBe` True
    it "refuses a k sharing a factor with p-1" $
        -- p is an odd prime, so p-1 is even and no even k is coprime with it
        mapM_
            (\k' -> ElGamal.signWith k' params priv SHA256 msg `shouldBe` Nothing)
            [2, 4, p - 3]
    it "rejects a signature over a different message" $
        case ElGamal.signWith k params priv SHA256 msg of
            Nothing -> expectationFailure "expected a signature"
            Just sig ->
                ElGamal.verify params pub SHA256 ("other" :: ByteString) sig
                    `shouldBe` False
    it "rejects a signature with r out of range" $
        ElGamal.verify params pub SHA256 msg (ElGamal.Signature 0 1) `shouldBe` False
    -- 'sign' draws a blinder for the inversion of k, so it takes a path
    -- 'signWith' does not: the inverse comes back from a different number
    -- than the one wanted, times the blinder
    it "verifies what it signs when it draws k itself" $
        mapM_
            ( \seed ->
                let (sig, _) =
                        withDRG (drgNewTest seed) (ElGamal.sign params priv SHA256 msg)
                 in ElGamal.verify params pub SHA256 msg sig `shouldBe` True
            )
            [ (1, 2, 3, 4, 5)
            , (5, 4, 3, 2, 1)
            , (0, 0, 0, 0, 1)
            , (9, 8, 7, 6, 5)
            , (0x1234, 0x5678, 0x9abc, 0xdef0, 0x2468)
            ]
  where
    msg = "message" :: ByteString
    k = 0x5d79a2c4e60813579bdf2468ace01f3b

spec :: Spec
spec = do
    encryptionTests
    decryptionTests
    signatureTests
