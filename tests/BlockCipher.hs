{-# LANGUAGE ViewPatterns #-}

module BlockCipher (
    KAT_ECB (..),
    KAT_CBC (..),
    KAT_CFB (..),
    KAT_CTR (..),
    KAT_XTS (..),
    KAT_AEAD (..),
    KATs (..),
    defaultKATs,
    testBlockCipher,
    testBlockCipher128,
    CipherInfo,
) where

import Crypto.Cipher.Types
import Crypto.Error
import Data.ByteArray as B hiding (length, null, pack)
import qualified Data.ByteString as B hiding (all, replicate, take)
import Data.Maybe
import Imports

------------------------------------------------------------------------
-- KAT
------------------------------------------------------------------------

type BlockSize = Int
type KeySize = Int
type CipherInfo a = (BlockSize, KeySize, ByteString -> a)

instance Show (IV c) where
    show _ = "IV"

-- | ECB KAT
data KAT_ECB = KAT_ECB
    { ecbKey :: ByteString
    -- ^ Key
    , ecbPlaintext :: ByteString
    -- ^ Plaintext
    , ecbCiphertext :: ByteString
    -- ^ Ciphertext
    }
    deriving (Show, Eq)

-- | CBC KAT
data KAT_CBC = KAT_CBC
    { cbcKey :: ByteString
    -- ^ Key
    , cbcIV :: ByteString
    -- ^ IV
    , cbcPlaintext :: ByteString
    -- ^ Plaintext
    , cbcCiphertext :: ByteString
    -- ^ Ciphertext
    }
    deriving (Show, Eq)

-- | CFB KAT
data KAT_CFB = KAT_CFB
    { cfbKey :: ByteString
    -- ^ Key
    , cfbIV :: ByteString
    -- ^ IV
    , cfbPlaintext :: ByteString
    -- ^ Plaintext
    , cfbCiphertext :: ByteString
    -- ^ Ciphertext
    }
    deriving (Show, Eq)

-- | CTR KAT
data KAT_CTR = KAT_CTR
    { ctrKey :: ByteString
    -- ^ Key
    , ctrIV :: ByteString
    -- ^ IV (usually represented as a 128 bits integer)
    , ctrPlaintext :: ByteString
    -- ^ Plaintext
    , ctrCiphertext :: ByteString
    -- ^ Ciphertext
    }
    deriving (Show, Eq)

-- | XTS KAT
data KAT_XTS = KAT_XTS
    { xtsKey1 :: ByteString
    -- ^ 1st XTS key
    , xtsKey2 :: ByteString
    -- ^ 2nd XTS key
    , xtsIV :: ByteString
    -- ^ XTS IV
    , xtsPlaintext :: ByteString
    -- ^ plaintext
    , xtsCiphertext :: ByteString
    -- ^ Ciphertext
    }
    deriving (Show, Eq)

-- | AEAD KAT
data KAT_AEAD = KAT_AEAD
    { aeadMode :: AEADMode
    , aeadKey :: ByteString
    -- ^ Key
    , aeadIV :: ByteString
    -- ^ IV for initialization
    , aeadHeader :: ByteString
    -- ^ Authenticated Header
    , aeadPlaintext :: ByteString
    -- ^ Plaintext
    , aeadCiphertext :: ByteString
    -- ^ Ciphertext
    , aeadTaglen :: Int
    -- ^ aead tag len
    , aeadTag :: ByteString
    -- ^ expected tag
    }
    deriving (Show, Eq)

-- | all the KATs. use defaultKATs to prevent compilation error
-- from future expansion of this data structure
data KATs = KATs
    { kat_ECB :: [KAT_ECB]
    , kat_CBC :: [KAT_CBC]
    , kat_CFB :: [KAT_CFB]
    , kat_CTR :: [KAT_CTR]
    , kat_XTS :: [KAT_XTS]
    , kat_AEAD :: [KAT_AEAD]
    }
    deriving (Show, Eq)

defaultKATs = KATs [] [] [] [] [] []

{-
testECB (_, _, cipherInit) ecbEncrypt ecbDecrypt kats =
    describe "ECB" $ mapM_ (katTest (zip is kats) {- ++ propTests-})
  where katTest (i,d) =
            [ it ("E" ++ show i) (ecbEncrypt ctx (ecbPlaintext d) `shouldBe` ecbCiphertext d)
            , it ("D" ++ show i) (ecbDecrypt ctx (ecbCiphertext d) `shouldBe` ecbPlaintext d)
            ]
          where ctx = cipherInit (ecbKey d)
        --propTest = prop "decrypt.encrypt" (ECBUnit key plaintext) =

        --testProperty_ECB (ECBUnit (cipherInit -> ctx) (toBytes -> plaintext)) =
        --    plaintext `assertEq` ecbDecrypt ctx (ecbEncrypt ctx plaintext)

testKatCBC cbcInit cbcEncrypt cbcDecrypt (i,d) =
    [ it ("E" ++ show i) (cbcEncrypt ctx iv (cbcPlaintext d) `shouldBe` cbcCiphertext d)
    , it ("D" ++ show i) (cbcDecrypt ctx iv (cbcCiphertext d) `shouldBe` cbcPlaintext d)
    ]
  where ctx = cbcInit $ cbcKey d
        iv  = cbcIV d

testKatCFB cfbInit cfbEncrypt cfbDecrypt (i,d) =
    [ it ("E" ++ show i) (cfbEncrypt ctx iv (cfbPlaintext d) `shouldBe` cfbCiphertext d)
    , it ("D" ++ show i) (cfbDecrypt ctx iv (cfbCiphertext d) `shouldBe` cfbPlaintext d)
    ]
  where ctx = cfbInit $ cfbKey d
        iv  = cfbIV d

testKatCTR ctrInit ctrCombine (i,d) =
    [ it ("E" ++ i) (ctrCombine ctx iv (ctrPlaintext d) `shouldBe` ctrCiphertext d)
    , it ("D" ++ i) (ctrCombine ctx iv (ctrCiphertext d) `shouldBe` ctrPlaintext d)
    ]
  where ctx = ctrInit $ ctrKey d
        iv  = ctrIV d

testKatXTS xtsInit xtsEncrypt xtsDecrypt (i,d) =
    [ it ("E" ++ i) (xtsEncrypt ctx iv 0 (xtsPlaintext d) `shouldBe` xtsCiphertext d)
    , it ("D" ++ i) (xtsDecrypt ctx iv 0 (xtsCiphertext d) `shouldBe` xtsPlaintext d)
    ]
  where ctx  = xtsInit (xtsKey1 d, xtsKey2 d)
        iv   = xtsIV d

testKatAEAD cipherInit aeadInit aeadAppendHeader aeadEncrypt aeadDecrypt aeadFinalize (i,d) =
    [ it ("AE" ++ i) (etag `shouldBe` aeadTag d)
    , it ("AD" ++ i) (dtag `shouldBe` aeadTag d)
    , it ("E" ++ i)  (ebs `shouldBe` aeadCiphertext d)
    , it ("D" ++ i)  (dbs `shouldBe` aeadPlaintext d)
    ]
  where ctx              = cipherInit $ aeadKey d
        (Just aead)      = aeadInit ctx (aeadIV d)
        aeadHeaded       = aeadAppendHeader aead (aeadHeader d)
        (ebs,aeadEFinal) = aeadEncrypt aeadHeaded (aeadPlaintext d)
        (dbs,aeadDFinal) = aeadDecrypt aeadHeaded (aeadCiphertext d)
        etag = aeadFinalize aeadEFinal (aeadTaglen d)
        dtag = aeadFinalize aeadDFinal (aeadTaglen d)
-}

testKATs
    :: BlockCipher cipher
    => KATs
    -> cipher
    -> Spec
testKATs kats cipher = describe "KAT" $ do
    maybeGroup makeECBTest "ECB" (kat_ECB kats)
    maybeGroup makeCBCTest "CBC" (kat_CBC kats)
    maybeGroup makeCFBTest "CFB" (kat_CFB kats)
    maybeGroup makeCTRTest "CTR" (kat_CTR kats)
    -- XTS needs a 128-bit block, so testBlockCipher128 runs kat_XTS
    maybeGroup makeAEADTest "AEAD" (kat_AEAD kats)
  where
    makeECBTest i d = do
        it ("E" ++ i) (ecbEncrypt ctx (ecbPlaintext d) `shouldBe` ecbCiphertext d)
        it ("D" ++ i) (ecbDecrypt ctx (ecbCiphertext d) `shouldBe` ecbPlaintext d)
      where
        ctx = cipherInitNoErr (cipherMakeKey cipher $ ecbKey d)
    makeCBCTest i d = do
        it ("E" ++ i) (cbcEncrypt ctx iv (cbcPlaintext d) `shouldBe` cbcCiphertext d)
        it ("D" ++ i) (cbcDecrypt ctx iv (cbcCiphertext d) `shouldBe` cbcPlaintext d)
      where
        ctx = cipherInitNoErr (cipherMakeKey cipher $ cbcKey d)
        iv = cipherMakeIV cipher $ cbcIV d
    makeCFBTest i d = do
        it ("E" ++ i) (cfbEncrypt ctx iv (cfbPlaintext d) `shouldBe` cfbCiphertext d)
        it ("D" ++ i) (cfbDecrypt ctx iv (cfbCiphertext d) `shouldBe` cfbPlaintext d)
      where
        ctx = cipherInitNoErr (cipherMakeKey cipher $ cfbKey d)
        iv = cipherMakeIV cipher $ cfbIV d
    makeCTRTest i d = do
        it ("E" ++ i) (ctrCombine ctx iv (ctrPlaintext d) `shouldBe` ctrCiphertext d)
        it ("D" ++ i) (ctrCombine ctx iv (ctrCiphertext d) `shouldBe` ctrPlaintext d)
      where
        ctx = cipherInitNoErr (cipherMakeKey cipher $ ctrKey d)
        iv = cipherMakeIV cipher $ ctrIV d
    makeAEADTest i d = do
        it ("AE" ++ i) (etag `shouldBe` AuthTag (B.convert (aeadTag d)))
        it ("AD" ++ i) (dtag `shouldBe` AuthTag (B.convert (aeadTag d)))
        it ("E" ++ i) (ebs `shouldBe` aeadCiphertext d)
        it ("D" ++ i) (dbs `shouldBe` aeadPlaintext d)
      where
        ctx = cipherInitNoErr (cipherMakeKey cipher $ aeadKey d)
        aead = aeadInitNoErr (aeadMode d) ctx (aeadIV d)
        aeadHeaded = aeadAppendHeader aead (aeadHeader d)
        (ebs, aeadEFinal) = aeadEncrypt aeadHeaded (aeadPlaintext d)
        (dbs, aeadDFinal) = aeadDecrypt aeadHeaded (aeadCiphertext d)
        etag = aeadFinalize aeadEFinal (aeadTaglen d)
        dtag = aeadFinalize aeadDFinal (aeadTaglen d)

    cipherInitNoErr :: BlockCipher c => Key c -> c
    cipherInitNoErr (Key k) =
        case cipherInit k of
            CryptoPassed a -> a
            CryptoFailed e -> error (show e)

    aeadInitNoErr
        :: (ByteArrayAccess iv, BlockCipher cipher)
        => AEADMode -> cipher -> iv -> AEAD cipher
    aeadInitNoErr mode ct iv =
        case aeadInit mode ct iv of
            CryptoPassed a -> a
            CryptoFailed _ -> error $ "cipher doesn't support aead mode: " ++ show mode

------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------

-- | any sized bytestring
newtype Plaintext a = Plaintext {unPlaintext :: B.ByteString}
    deriving (Show, Eq)

-- | A multiple of blocksize bytestring
newtype PlaintextBS a = PlaintextBS {unPlaintextBS :: B.ByteString}
    deriving (Show, Eq)

newtype Key a = Key ByteString
    deriving (Show, Eq)

-- | a ECB unit test
data ECBUnit a = ECBUnit (Key a) (PlaintextBS a)
    deriving (Eq)

-- | a CBC unit test
data CBCUnit a = CBCUnit (Key a) (IV a) (PlaintextBS a)
    deriving (Eq)

-- | a CBC unit test
data CFBUnit a = CFBUnit (Key a) (IV a) (PlaintextBS a)
    deriving (Eq)

-- | a CFB unit test
data CFB8Unit a = CFB8Unit (Key a) (IV a) (Plaintext a)
    deriving (Eq)

-- | a CTR unit test
data CTRUnit a = CTRUnit (Key a) (IV a) (Plaintext a)
    deriving (Eq)

-- | a XTS unit test
data XTSUnit a = XTSUnit (Key a) (Key a) (IV a) (PlaintextBS a)
    deriving (Eq)

-- | a AEAD unit test
data AEADUnit a = AEADUnit (Key a) B.ByteString (Plaintext a) (Plaintext a)
    deriving (Eq)

-- | Stream cipher unit test
data StreamUnit a = StreamUnit (Key a) (Plaintext a)
    deriving (Eq)

instance Show (ECBUnit a) where
    show (ECBUnit key b) = "ECB(key=" ++ show key ++ ",input=" ++ show b ++ ")"
instance Show (CBCUnit a) where
    show (CBCUnit key iv b) = "CBC(key=" ++ show key ++ ",iv=" ++ show iv ++ ",input=" ++ show b ++ ")"
instance Show (CFBUnit a) where
    show (CFBUnit key iv b) = "CFB(key=" ++ show key ++ ",iv=" ++ show iv ++ ",input=" ++ show b ++ ")"
instance Show (CFB8Unit a) where
    show (CFB8Unit key iv b) = "CFB8(key=" ++ show key ++ ",iv=" ++ show iv ++ ",input=" ++ show b ++ ")"
instance Show (CTRUnit a) where
    show (CTRUnit key iv b) = "CTR(key=" ++ show key ++ ",iv=" ++ show iv ++ ",input=" ++ show b ++ ")"
instance Show (XTSUnit a) where
    show (XTSUnit key1 key2 iv b) =
        "XTS(key1="
            ++ show key1
            ++ ",key2="
            ++ show key2
            ++ ",iv="
            ++ show iv
            ++ ",input="
            ++ show b
            ++ ")"
instance Show (AEADUnit a) where
    show (AEADUnit key iv aad b) =
        "AEAD(key="
            ++ show key
            ++ ",iv="
            ++ show iv
            ++ ",aad="
            ++ show (unPlaintext aad)
            ++ ",input="
            ++ show b
            ++ ")"
instance Show (StreamUnit a) where
    show (StreamUnit key b) = "Stream(key=" ++ show key ++ ",input=" ++ show b ++ ")"

-- | Generate an arbitrary valid key for a specific block cipher
generateKey :: Cipher a => Gen (Key a)
generateKey = keyFromCipher undefined
  where
    keyFromCipher :: Cipher a => a -> Gen (Key a)
    keyFromCipher cipher = do
        sz <- case cipherKeySize cipher of
            KeySizeRange low high -> choose (low, high)
            KeySizeFixed v -> return v
            KeySizeEnum l -> elements l
        Key . B.pack <$> replicateM sz arbitrary

-- | Generate an arbitrary valid IV for a specific block cipher
generateIv :: BlockCipher a => Gen (IV a)
generateIv = ivFromCipher undefined
  where
    ivFromCipher :: BlockCipher a => a -> Gen (IV a)
    ivFromCipher cipher = fromJust . makeIV . B.pack <$> replicateM (blockSize cipher) arbitrary

-- | Generate an arbitrary valid IV for AEAD for a specific block cipher
generateIvAEAD :: Gen B.ByteString
generateIvAEAD = choose (12, 90) >>= \sz -> (B.pack <$> replicateM sz arbitrary)

-- | Generate a plaintext multiple of blocksize bytes
generatePlaintextMultipleBS :: BlockCipher a => Gen (PlaintextBS a)
generatePlaintextMultipleBS =
    choose (1, 128) >>= \size -> replicateM (size * 16) arbitrary >>= return . PlaintextBS . B.pack

-- | Generate any sized plaintext
generatePlaintext :: Gen (Plaintext a)
generatePlaintext =
    choose (0, 324) >>= \size -> replicateM size arbitrary >>= return . Plaintext . B.pack

instance BlockCipher a => Arbitrary (ECBUnit a) where
    arbitrary =
        ECBUnit
            <$> generateKey
            <*> generatePlaintextMultipleBS

instance BlockCipher a => Arbitrary (CBCUnit a) where
    arbitrary =
        CBCUnit
            <$> generateKey
            <*> generateIv
            <*> generatePlaintextMultipleBS

instance BlockCipher a => Arbitrary (CFBUnit a) where
    arbitrary =
        CFBUnit
            <$> generateKey
            <*> generateIv
            <*> generatePlaintextMultipleBS

instance BlockCipher a => Arbitrary (CFB8Unit a) where
    arbitrary = CFB8Unit <$> generateKey <*> generateIv <*> generatePlaintext

instance BlockCipher a => Arbitrary (CTRUnit a) where
    arbitrary =
        CTRUnit
            <$> generateKey
            <*> generateIv
            <*> generatePlaintext

instance BlockCipher a => Arbitrary (XTSUnit a) where
    arbitrary =
        XTSUnit
            <$> generateKey
            <*> generateKey
            <*> generateIv
            <*> generatePlaintextMultipleBS

instance BlockCipher a => Arbitrary (AEADUnit a) where
    arbitrary =
        AEADUnit
            <$> generateKey
            <*> generateIvAEAD
            <*> generatePlaintext
            <*> generatePlaintext

instance StreamCipher a => Arbitrary (StreamUnit a) where
    arbitrary =
        StreamUnit
            <$> generateKey
            <*> generatePlaintext

testBlockCipherBasic :: BlockCipher a => a -> Spec
testBlockCipherBasic cipher = prop "ECB" ecbProp
  where
    ecbProp = toTests cipher
    toTests :: BlockCipher a => a -> (ECBUnit a -> Bool)
    toTests _ = testProperty_ECB
    testProperty_ECB (ECBUnit key (unPlaintextBS -> plaintext)) = withCtx key $ \ctx ->
        plaintext `assertEq` ecbDecrypt ctx (ecbEncrypt ctx plaintext)

testBlockCipherModes :: BlockCipher a => a -> Spec
testBlockCipherModes cipher = do
    prop "CBC" cbcProp
    prop "CFB" cfbProp
    -- prop "CFB8" cfb8Prop
    prop "CTR" ctrProp
  where
    (cbcProp, cfbProp, ctrProp) = toTests cipher
    toTests
        :: BlockCipher a
        => a
        -> ( (CBCUnit a -> Bool)
           , (CFBUnit a -> Bool {-(CFB8Unit a -> Bool),-})
           , (CTRUnit a -> Bool)
           )
    toTests _ =
        ( testProperty_CBC
        , testProperty_CFB
        , -- ,testProperty_CFB8
          testProperty_CTR
        )
    testProperty_CBC (CBCUnit key testIV (unPlaintextBS -> plaintext)) = withCtx key $ \ctx ->
        plaintext `assertEq` cbcDecrypt ctx testIV (cbcEncrypt ctx testIV plaintext)

    testProperty_CFB (CFBUnit key testIV (unPlaintextBS -> plaintext)) = withCtx key $ \ctx ->
        plaintext `assertEq` cfbDecrypt ctx testIV (cfbEncrypt ctx testIV plaintext)

    {-
            testProperty_CFB8 (CFB8Unit (cipherInit -> ctx) testIV (unPlaintext -> plaintext)) =
                plaintext `assertEq` cfb8Decrypt ctx testIV (cfb8Encrypt ctx testIV plaintext)
    -}

    testProperty_CTR (CTRUnit key testIV (unPlaintext -> plaintext)) = withCtx key $ \ctx ->
        plaintext `assertEq` ctrCombine ctx testIV (ctrCombine ctx testIV plaintext)

testBlockCipherAEAD :: BlockCipher a => a -> Spec
testBlockCipherAEAD cipher = do
    prop "OCB" (aeadProp AEAD_OCB)
    prop "CCM" (aeadProp (AEAD_CCM 0 CCM_M16 CCM_L2))
    prop "EAX" (aeadProp AEAD_EAX)
    prop "CWC" (aeadProp AEAD_CWC)
    prop "GCM" (aeadProp AEAD_GCM)
  where
    aeadProp = toTests cipher
    toTests :: BlockCipher a => a -> (AEADMode -> AEADUnit a -> Bool)
    toTests _ = testProperty_AEAD
    testProperty_AEAD mode (AEADUnit key testIV (unPlaintext -> aad) (unPlaintext -> plaintext)) = withCtx key $ \ctx ->
        case aeadInit mode' ctx iv' of
            CryptoPassed iniAead ->
                let aead = aeadAppendHeader iniAead aad
                    (eText, aeadE) = aeadEncrypt aead plaintext
                    (dText, aeadD) = aeadDecrypt aead eText
                    eTag = aeadFinalize aeadE (blockSize ctx)
                    dTag = aeadFinalize aeadD (blockSize ctx)
                 in (plaintext `assertEq` dText) && (eTag `B.eq` dTag)
            CryptoFailed err
                | err == CryptoError_AEADModeNotSupported -> True
                | otherwise ->
                    error ("testProperty_AEAD: " ++ show err)
      where
        (mode', iv') = updateCcmInputSize mode (B.length plaintext) testIV
        updateCcmInputSize aeadmode k iv = case aeadmode of
            AEAD_CCM _ m l -> (AEAD_CCM k m l, B.take 13 (iv <> (B.replicate 15 0)))
            aeadOther -> (aeadOther, iv)

withCtx :: Cipher c => Key c -> (c -> a) -> a
withCtx (Key key) f =
    case cipherInit key of
        CryptoFailed e -> error ("init failed: " ++ show e)
        CryptoPassed ctx -> f ctx

{-
testBlockCipherXTS :: BlockCipher a => a -> [Spec]
testBlockCipherXTS cipher = [prop "XTS" xtsProp]
  where xtsProp = toTests cipher
        toTests :: BlockCipher a => a -> (XTSUnit a -> Bool)
        toTests _ = testProperty_XTS

        testProperty_XTS (XTSUnit (cipherInit -> ctx1) (cipherInit -> ctx2) testIV (toBytes -> plaintext))
            | blockSize ctx1 == 16 = plaintext `assertEq` xtsDecrypt (ctx1, ctx2) testIV 0 (xtsEncrypt (ctx1, ctx2) testIV 0 plaintext)
            | otherwise            = True
-}

-- | Test a generic block cipher for properties
-- related to block cipher modes.
testModes :: BlockCipher a => a -> Spec
testModes cipher =
    describe "decrypt.encrypt==id" $ do
        testBlockCipherBasic cipher
        testBlockCipherModes cipher
        testBlockCipherAEAD cipher

-- | Test IV arithmetic (based on the cipher block size)
testIvArith :: BlockCipher a => a -> Spec
testIvArith cipher = do
    it "nullIV is null" $
        B.all (== 0) (ivNull cipher) `shouldBe` True
    prop "ivAdd is linear" $ \a b -> do
        iv <- generateIvFromCipher cipher
        return $ ivAdd iv (a + b) `propertyEq` ivAdd (ivAdd iv a) b
  where
    ivNull :: BlockCipher a => a -> IV a
    ivNull = const nullIV

    -- uses IV pattern <00 .. 00 FF .. FF> to test carry propagation
    generateIvFromCipher :: BlockCipher a => a -> Gen (IV a)
    generateIvFromCipher c = do
        let n = blockSize c
        i <- choose (0, n)
        let zeros = Prelude.replicate (n - i) 0x00
            ones = Prelude.replicate i 0xFF
        return $ cipherMakeIV c (B.pack $ zeros ++ ones)

-- | Return tests for a specific blockcipher and a list of KATs
testBlockCipher :: BlockCipher a => KATs -> a -> Spec
testBlockCipher = testBlockCipherWith (return ())

-- | The same for a cipher with a 128-bit block, whose KATs may include XTS.
-- The mode is defined only for that block size, so its vectors cannot run
-- from 'testBlockCipher', which promises nothing about the size -- which is
-- how they came to sit in the tree unused.
testBlockCipher128 :: BlockCipher128 a => KATs -> a -> Spec
testBlockCipher128 kats cipher =
    testBlockCipherWith
        (maybeGroup (makeXTSTest cipher) "XTS" (kat_XTS kats))
        kats
        cipher

testBlockCipherWith :: BlockCipher a => Spec -> KATs -> a -> Spec
testBlockCipherWith extra kats cipher =
    describe (cipherName cipher) $ do
        unless (kats == defaultKATs) $ testKATs kats cipher
        extra
        testModes cipher
        testIvArith cipher

makeXTSTest :: BlockCipher128 cipher => cipher -> String -> KAT_XTS -> Spec
makeXTSTest cipher i d = do
    it ("E" ++ i) (xtsEncrypt ctx iv 0 (xtsPlaintext d) `shouldBe` xtsCiphertext d)
    it ("D" ++ i) (xtsDecrypt ctx iv 0 (xtsCiphertext d) `shouldBe` xtsPlaintext d)
  where
    ctx = (keyed (xtsKey1 d), keyed (xtsKey2 d))
    iv = cipherMakeIV cipher (xtsIV d)

    keyed :: BlockCipher c => ByteString -> c
    keyed k =
        case cipherInit k of
            CryptoPassed a -> a
            CryptoFailed e -> error (show e)

cipherMakeKey :: Cipher cipher => cipher -> ByteString -> Key cipher
cipherMakeKey _ bs = Key bs

cipherMakeIV :: BlockCipher cipher => cipher -> ByteString -> IV cipher
cipherMakeIV _ bs = fromJust $ makeIV bs

maybeGroup :: (String -> t -> Spec) -> String -> [t] -> Spec
maybeGroup mkTest groupName l
    | null l = return ()
    | otherwise =
        describe groupName $ mapM_ (\(i, d) -> mkTest (show i) d) (zip nbs l)
  where
    nbs :: [Int]
    nbs = [0 ..]
