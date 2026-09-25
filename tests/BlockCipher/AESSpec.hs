{-# LANGUAGE OverloadedStrings #-}

module BlockCipher.AESSpec (spec) where

import BlockCipher
import qualified Crypto.Cipher.AES as AES
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash (Digest, SHA256, hash)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.Maybe
import Imports

import qualified BlockCipher.AES.CBC as KATCBC
import qualified BlockCipher.AES.CCM as KATCCM
import qualified BlockCipher.AES.CTR as KATCTR
import qualified BlockCipher.AES.ECB as KATECB
import qualified BlockCipher.AES.GCM as KATGCM
import qualified BlockCipher.AES.GCMLong as KATGCMLong
import qualified BlockCipher.AES.OCB3 as KATOCB3
import qualified BlockCipher.AES.XTS as KATXTS
import qualified Crypto.Cipher.AES.GCM as GCM
import Data.Bits (xor)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (castPtr)

{-
instance Show AES.AES where
    show _ = "AES"
instance Arbitrary AES.AESIV where
    arbitrary = AES.aesIV_ . B.pack <$> replicateM 16 arbitrary
instance Arbitrary AES.AES where
    arbitrary = AES.initAES . B.pack <$> replicateM 16 arbitrary
-}

toKatECB (k, p, c) = KAT_ECB{ecbKey = k, ecbPlaintext = p, ecbCiphertext = c}
toKatCBC (k, iv, p, c) = KAT_CBC{cbcKey = k, cbcIV = iv, cbcPlaintext = p, cbcCiphertext = c}
toKatCTR (k, iv, p, c) = KAT_CTR{ctrKey = k, ctrIV = iv, ctrPlaintext = p, ctrCiphertext = c}
toKatXTS (k1, k2, iv, p, _, c) =
    KAT_XTS
        { xtsKey1 = k1
        , xtsKey2 = k2
        , xtsIV = iv
        , xtsPlaintext = p
        , xtsCiphertext = c
        }
toKatAEAD mode (k, iv, h, p, c, taglen, tag) =
    KAT_AEAD
        { aeadMode = mode
        , aeadKey = k
        , aeadIV = iv
        , aeadHeader = h
        , aeadPlaintext = p
        , aeadCiphertext = c
        , aeadTaglen = taglen
        , aeadTag = tag
        }
toKatGCM = toKatAEAD AEAD_GCM
toKatOCB = toKatAEAD AEAD_OCB

toKatCCM (k, iv, h, i, o, m) =
    KAT_AEAD
        { aeadMode = AEAD_CCM (B.length i) (ccmMVal m) CCM_L2
        , aeadKey = k
        , aeadIV = iv
        , aeadHeader = h
        , aeadPlaintext = i
        , aeadCiphertext = ct
        , aeadTaglen = m
        , aeadTag = at
        }
  where
    ccmMVal x =
        fromMaybe (error $ "unsupported CCM tag length: " ++ show x) $
            lookup
                x
                [ (4, CCM_M4)
                , (6, CCM_M6)
                , (8, CCM_M8)
                , (10, CCM_M10)
                , (12, CCM_M12)
                , (14, CCM_M14)
                , (16, CCM_M16)
                ]
    ctWithTag = B.drop (B.length h) o
    (ct, at) = B.splitAt (B.length ctWithTag - m) ctWithTag

kats128 =
    defaultKATs
        { kat_ECB = map toKatECB KATECB.vectors_aes128_enc
        , kat_CBC = map toKatCBC KATCBC.vectors_aes128_enc
        , kat_CTR = map toKatCTR KATCTR.vectors_aes128_enc
        , kat_CFB =
            [ KAT_CFB
                { cfbKey =
                    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
                , cfbIV =
                    "\xC8\xA6\x45\x37\xA0\xB3\xA9\x3F\xCD\xE3\xCD\xAD\x9F\x1C\xE5\x8B"
                , cfbPlaintext =
                    "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
                , cfbCiphertext =
                    "\x26\x75\x1f\x67\xa3\xcb\xb1\x40\xb1\x80\x8c\xf1\x87\xa4\xf4\xdf"
                }
            ]
        , kat_XTS = map toKatXTS KATXTS.vectors_aes128_enc
        , kat_AEAD =
            map toKatGCM KATGCM.vectors_aes128_enc
                ++ map toKatOCB KATOCB3.vectors_aes128_enc
                ++ map toKatCCM KATCCM.vectors_aes128_enc
        }

kats192 =
    defaultKATs
        { kat_ECB = map toKatECB KATECB.vectors_aes192_enc
        , kat_CBC = map toKatCBC KATCBC.vectors_aes192_enc
        , kat_CTR = map toKatCTR KATCTR.vectors_aes192_enc
        , kat_AEAD =
            map toKatGCM KATGCM.vectors_aes192_enc
                ++ map toKatOCB KATOCB3.vectors_aes192_enc
                ++ map toKatCCM KATCCM.vectors_aes192_enc
        }

kats256 =
    defaultKATs
        { kat_ECB = map toKatECB KATECB.vectors_aes256_enc
        , kat_CBC = map toKatCBC KATCBC.vectors_aes256_enc
        , kat_CTR = map toKatCTR KATCTR.vectors_aes256_enc
        , kat_XTS = map toKatXTS KATXTS.vectors_aes256_enc
        , kat_AEAD =
            map toKatGCM KATGCM.vectors_aes256_enc
                ++ map toKatOCB KATOCB3.vectors_aes256_enc
                ++ map toKatCCM KATCCM.vectors_aes256_enc
        }

-- SP 800-38D 5.2.1.1: 1 <= len(IV) <= 2^64 - 1.  A zero-length IV makes
-- J0 the GHASH of the empty string, which leaks the authentication key.
aeadIVLengthTests :: Spec
aeadIVLengthTests =
    describe "AEAD IV length" $ do
        it "96-bit IV accepted" $
            isRight (initWith (B.replicate 12 0)) `shouldBe` True
        it "8-bit IV accepted" $
            isRight (initWith (B.replicate 1 0)) `shouldBe` True
        it "empty IV rejected" $
            initWith B.empty `shouldBe` Left CryptoError_IvSizeInvalid
  where
    ctx = throwCryptoError (cipherInit (B.replicate 16 0)) :: AES.AES128
    initWith iv =
        eitherCryptoError (() <$ aeadInit AEAD_GCM ctx (iv :: ByteString))
    isRight = either (const False) (const True)

aeadTagLengthTests :: Spec
aeadTagLengthTests =
    describe "AEAD tag length" $ do
        it "full tag verifies" $ openWith fullTag `shouldBe` Just message
        it "empty tag rejected" $ openWith B.empty `shouldBe` Nothing
        it "1-byte tag rejected" $ openWith (B.take 1 fullTag) `shouldBe` Nothing
        it "3-byte tag rejected" $ openWith (B.take 3 fullTag) `shouldBe` Nothing
        it "wrong tag rejected" $
            openWith (B.map (+ 1) fullTag) `shouldBe` Nothing
        -- a truncated tag is still at or above the minimum, so the length
        -- taken from the tag is the peer's choice of how much to verify
        it "4-byte tag accepted, since the tag sets the length" $
            openWith (B.take 4 fullTag) `shouldBe` Just message
        it "tryAeadSimpleDecrypt verifies the full tag" $
            openWith' 16 fullTag `shouldBe` Just message
        it "tryAeadSimpleDecrypt refuses a truncated tag" $
            openWith' 16 (B.take 4 fullTag) `shouldBe` Nothing
        it "tryAeadSimpleDecrypt refuses an overlong tag" $
            openWith' 16 (fullTag `B.append` B.singleton 0) `shouldBe` Nothing
        it "tryAeadSimpleDecrypt refuses a length below the minimum" $
            openWith' 3 (B.take 3 fullTag) `shouldBe` Nothing
        it "tryAeadSimpleDecrypt verifies a short tag the caller asked for" $
            openWith' 8 (B.take 8 fullTag) `shouldBe` Just message
        it "tryAeadSimpleDecrypt refuses a wrong tag" $
            openWith' 16 (B.map (+ 1) fullTag) `shouldBe` Nothing
  where
    key = B.replicate 16 0
    iv = B.replicate 12 0
    aad = "additional data" :: ByteString
    message = "authenticated message" :: ByteString
    ctx = throwCryptoError (cipherInit key) :: AES.AES128
    aead = throwCryptoError (aeadInit AEAD_GCM ctx iv)
    (AuthTag tag, ciphertext) = aeadSimpleEncrypt aead aad message 16
    fullTag = BA.convert tag :: ByteString
    openWith t = aeadSimpleDecrypt aead aad ciphertext (AuthTag (BA.convert t))
    openWith' n t = tryAeadSimpleDecrypt aead aad ciphertext n (AuthTag (BA.convert t))

-- The bulk loops -- eight blocks at a time under AES-NI, six at a time in
-- the assembly -- only start once the message is long enough to fill them,
-- and what they leave over goes down a different path.  These lengths sit
-- either side of each of those boundaries, so a group that hashes the wrong
-- blocks or a tail that is picked up at the wrong offset shows up here.
gcmLongTests :: Spec
gcmLongTests =
    describe "GCM long messages" $ mapM_ test KATGCMLong.vectors
  where
    test v@(klen, aadlen, ptlen, _, _) =
        it
            ( show klen
                ++ "-byte key, "
                ++ show aadlen
                ++ "-byte AAD, "
                ++ show ptlen
                ++ "-byte message"
            )
            $ case klen of
                16 -> run (undefined :: AES.AES128) v
                24 -> run (undefined :: AES.AES192) v
                _ -> run (undefined :: AES.AES256) v
    run
        :: BlockCipher cipher
        => cipher
        -> KATGCMLong.KATGCMLong
        -> Expectation
    run cipherWitness (klen, aadlen, ptlen, tag, ctHash) = do
        BA.convert authTag `shouldBe` tag
        digest ciphertext `shouldBe` ctHash
        aeadSimpleDecrypt aead aad ciphertext authTag `shouldBe` Just plaintext
      where
        cipher =
            throwCryptoError (cipherInit (KATGCMLong.gcmKey klen)) `asTypeOf` cipherWitness
        aead = throwCryptoError (aeadInit AEAD_GCM cipher KATGCMLong.gcmIV)
        aad = KATGCMLong.gcmAAD aadlen
        plaintext = KATGCMLong.gcmPlaintext ptlen
        (authTag, ciphertext) = aeadSimpleEncrypt aead aad plaintext 16
    digest bs = BA.convert (hash bs :: Digest SHA256) :: ByteString

-- | Crypto.Cipher.AES.GCM builds the key part of the state once and does a
-- whole message in one call.  It has to answer exactly what the general
-- interface answers, so it is run over the same vectors, and a tampered
-- message has to come back as Nothing rather than as plaintext.
oneShotTests :: Spec
oneShotTests = describe "Crypto.Cipher.AES.GCM" $ do
    describe "agrees with the general interface" $ do
        run "AES-128" KATGCM.vectors_aes128_enc
        run "AES-192" KATGCM.vectors_aes192_enc
        run "AES-256" KATGCM.vectors_aes256_enc
    describe "decryptWithTag hands back the tag encrypt made" $ do
        runTag "AES-128" KATGCM.vectors_aes128_enc
        runTag "AES-192" KATGCM.vectors_aes192_enc
        runTag "AES-256" KATGCM.vectors_aes256_enc
    it "decryptWithTag gives a different tag for a tampered ciphertext" $
        let ctx = ctx16
            sealed = GCM.encrypt ctx iv16 B.empty message 16 :: B.ByteString
            body = B.take (B.length sealed - 16) sealed
            tag = AuthTag (BA.convert (B.drop (B.length sealed - 16) sealed))
            (_, tag') =
                GCM.decryptWithTag ctx iv16 B.empty (flipFirst body) 16
                    :: (B.ByteString, AuthTag)
         in tag' `shouldSatisfy` (/= tag)
    describe "refuses a message that was interfered with" $ do
        it "a flipped bit in the tag" $ tamper (\(c, t) -> (c, flipFirst t))
        it "a flipped bit in the ciphertext" $ tamper (\(c, t) -> (flipFirst c, t))
    it "refuses input shorter than the tag" $
        (GCM.decrypt ctx16 iv16 B.empty (B.replicate 8 0) 16 :: Maybe B.ByteString)
            `shouldBe` Nothing
    describe "header protection" $ do
        it "writes the ciphertext encrypt gives" $
            withMask 4 `shouldReturn` Just (plainSealed, expectedMask 4)
        it "and at another offset" $
            withMask 0 `shouldReturn` Just (plainSealed, expectedMask 0)
        it "refuses a sample that does not fit, writing nothing" $ do
            withMask (B.length plainSealed - 15) `shouldReturn` Nothing
            withMask (-1) `shouldReturn` Nothing
  where
    run name vs =
        it name $
            [ (key, iv)
            | (key, iv, aad, input, out, taglen, tag) <- vs
            , let ctx = throwCryptoError (GCM.newContext key)
            , let sealed = GCM.encrypt ctx iv aad input taglen :: B.ByteString
            , sealed /= out `B.append` tag
                || GCM.decrypt ctx iv aad sealed taglen /= Just input
            ]
                `shouldBe` []
    -- The tag decryptWithTag computes has to be the one encrypt appended, and
    -- the body it returns the one decrypt returns, over the same vectors.
    runTag name vs =
        it name $
            [ (key, iv)
            | (key, iv, aad, input, out, taglen, tag) <- vs
            , let ctx = throwCryptoError (GCM.newContext key)
            , let (body, tag') =
                    GCM.decryptWithTag ctx iv aad out taglen
                        :: (B.ByteString, AuthTag)
            , body /= input || tag' /= AuthTag (BA.convert tag)
            ]
                `shouldBe` []
    ctx16 = throwCryptoError (GCM.newContext (B.replicate 16 0x2b))
    iv16 = B.replicate 12 0x77
    -- header protection keeps a key of its own, as QUIC does
    hpKeyBytes = B.replicate 16 0x9c
    hpKey = throwCryptoError (GCM.newHeaderKey hpKeyBytes)
    hpAes = throwCryptoError (cipherInit hpKeyBytes) :: AES.AES128
    message = "a packet payload" :: B.ByteString
    header = "\x40\x01\x02\x03" :: B.ByteString
    plainSealed = GCM.encrypt ctx16 iv16 header message 16 :: B.ByteString
    -- the buffers the caller owns, as a packet writer would have them
    withMask off =
        allocaBytes (B.length message + 16) $ \outp ->
            allocaBytes 16 $ \maskp -> do
                ok <- GCM.encryptWithMask ctx16 hpKey iv16 header message 16 off outp maskp
                if ok
                    then do
                        sealed <- B.packCStringLen (castPtr outp, B.length message + 16)
                        mask <- B.packCStringLen (castPtr maskp, 16)
                        return (Just (sealed, mask))
                    else return Nothing
    expectedMask off = ecbEncrypt hpAes (B.take 16 (B.drop off plainSealed))
    flipFirst b = B.cons (B.head b `xor` 1) (B.tail b)
    tamper f =
        let sealed = GCM.encrypt ctx16 iv16 B.empty ("hello there" :: B.ByteString) 16
            (c, t) = B.splitAt (B.length sealed - 16) sealed
            (c', t') = f (c, t)
         in (GCM.decrypt ctx16 iv16 B.empty (c' `B.append` t') 16 :: Maybe B.ByteString)
                `shouldBe` Nothing

spec :: Spec
spec = do
    testBlockCipher128 kats128 (undefined :: AES.AES128)
    testBlockCipher128 kats192 (undefined :: AES.AES192)
    testBlockCipher128 kats256 (undefined :: AES.AES256)
    aeadIVLengthTests
    aeadTagLengthTests
    gcmLongTests
    oneShotTests
