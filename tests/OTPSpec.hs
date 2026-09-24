{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}

module OTPSpec (
    spec,
)
where

import Control.Exception (evaluate)
import Crypto.Hash.Algorithms (
    Blake2b (..),
    MD5 (..),
    SHA1 (..),
    SHA256 (..),
    SHA512 (..),
 )
import Crypto.OTP
import qualified Crypto.OTP as TOTP
import Data.Either (isLeft)
import Imports

-- | Test values from Appendix D of http://tools.ietf.org/html/rfc4226
hotpExpected :: [(Word64, Word32)]
hotpExpected =
    [ (0, 755224)
    , (1, 287082)
    , (3, 969429)
    , (4, 338314)
    , (5, 254676)
    , (6, 287922)
    , (7, 162583)
    , (8, 399871)
    , (9, 520489)
    ]

-- | Test data from Appendix B of http://tools.ietf.org/html/rfc6238
-- Note that the shared keys for the non SHA-1 values are actually
-- different (see the errata, or the Java example code).
totpSHA1Expected :: [(Word64, Word32)]
totpSHA1Expected =
    [ (59, 94287082)
    , (1111111109, 07081804)
    , (1111111111, 14050471)
    , (1234567890, 89005924)
    , (2000000000, 69279037)
    , (20000000000, 65353130)
    ]

totpSHA256Expected :: [(Word64, Word32)]
totpSHA256Expected =
    [ (59, 46119246)
    , (1111111109, 68084774)
    , (1111111111, 67062674)
    , (1234567890, 91819424)
    , (2000000000, 90698825)
    , (20000000000, 77737706)
    ]

totpSHA512Expected :: [(Word64, Word32)]
totpSHA512Expected =
    [ (59, 90693936)
    , (1111111109, 25091201)
    , (1111111111, 99943326)
    , (1234567890, 93441116)
    , (2000000000, 38618901)
    , (20000000000, 47863826)
    ]

otpKey :: ByteString
otpKey = "12345678901234567890"

totpSHA256Key :: ByteString
totpSHA256Key = "12345678901234567890123456789012"

totpSHA512Key :: ByteString
totpSHA512Key =
    "1234567890123456789012345678901234567890123456789012345678901234"

makeKATs :: (Eq a, Show a) => (t -> a) -> [(t, a)] -> [Spec]
makeKATs otp expected = concatMap (makeTest otp) (zip3 is counts otps)
  where
    is :: [Int]
    is = [1 ..]

    counts = map fst expected
    otps = map snd expected

makeTest :: (Eq a1, Show a2, Show a1) => (t -> a1) -> (a2, t, a1) -> [Spec]
makeTest otp (i, count, password) =
    [ it (show i) (assertEqual "" password (otp count))
    ]

totpSHA1Params :: TOTPParams SHA1
totpSHA1Params = case mkTOTPParams SHA1 0 30 OTP8 TwoSteps of
    Right x -> x
    _ -> error "totpSHA1Params"

totpSHA256Params :: TOTPParams SHA256
totpSHA256Params = case mkTOTPParams SHA256 0 30 OTP8 TwoSteps of
    Right x -> x
    _ -> error "totpSHA256Params"

totpSHA512Params :: TOTPParams SHA512
totpSHA512Params = case mkTOTPParams SHA512 0 30 OTP8 TwoSteps of
    Right x -> x
    _ -> error "totpSHA512Params"

-- resynching with the expected value should just return the current counter + 1
prop_resyncExpected :: Word64 -> Word16 -> Bool
prop_resyncExpected ctr window = resynchronize SHA1 OTP6 window key ctr (otp, []) == Just (ctr + 1)
  where
    key = "1234" :: ByteString
    otp = hotp SHA1 OTP6 key ctr

-- | RFC 4226 dynamic truncation reads the offset from the low four bits of
-- the MAC's last byte, so the offset can be any of 0..15, and then reads four
-- bytes starting there -- reaching byte 18.  A digest shorter than that leaves
-- 'hotp' indexing past the end of the MAC, and 'Data.ByteArray.index' does not
-- bounds check, so the OTP is built from whatever happens to follow the MAC in
-- memory.  Such a digest must be refused instead.
digestSizeTests :: [Spec]
digestSizeTests =
    [ it "SHA-1 (20 bytes) is accepted" $
        hotp SHA1 OTP6 otpKey 1 `shouldBe` 287082
    , rejects "MD5 (16 bytes)" (hotp MD5 OTP6 otpKey 1)
    , rejects "Blake2b-64 (8 bytes)" (hotp (Blake2b :: Blake2b 64) OTP6 otpKey 1)
    , it "resynchronize with a short digest is rejected" $
        evaluate (resynchronize MD5 OTP6 10 otpKey 0 (0, []))
            `shouldThrow` anyErrorCall
    , it "mkTOTPParams rejects a short digest" $
        mkTOTPParams MD5 0 30 OTP6 TwoSteps `shouldSatisfy` isLeft
    ]
  where
    rejects name otp =
        it (name ++ " is rejected") $ evaluate otp `shouldThrow` anyErrorCall

-- | resynchronize hunts for the client's counter in a window of values
-- derived from the shared secret, and reports how far it got only through the
-- counter it returns.  Pin down which submissions it accepts, which it
-- refuses, and the counter each accepted one leaves behind, before that search
-- is rewritten.
resyncTests :: [Spec]
resyncTests =
    [ it "the value for the current counter moves the server on by one" $
        resync 20 (at 0, []) `shouldBe` serverAfter 1
    , it "a value from inside the window is found" $
        resync 20 (at 7, []) `shouldBe` serverAfter 8
    , it "the last value in the window is found" $
        resync 20 (at 20, []) `shouldBe` serverAfter 21
    , it "the value just past the window is not" $
        resync 20 (at 21, []) `shouldBe` Nothing
    , it "a value no counter produces is refused" $
        resync 20 (at 0 + 1, []) `shouldBe` Nothing
    , it "a window of zero looks at the current counter only" $ do
        resync 0 (at 0, []) `shouldBe` serverAfter 1
        resync 0 (at 1, []) `shouldBe` Nothing
    , it "the extra values carry the counter past all of them" $
        resync 20 (at 7, [at 8, at 9]) `shouldBe` serverAfter 10
    , it "an extra value that is wrong refuses the whole submission" $
        sequence_
            [ resync 20 (at 7, wrongAt i [at 8, at 9, at 10]) `shouldBe` Nothing
            | i <- [0 .. 2]
            ]
    , it "extra values that are right do not rescue a wrong first value" $
        resync 20 (at 0 + 1, [at 1, at 2]) `shouldBe` Nothing
    , it "extra values from the wrong counters are refused" $
        resync 20 (at 7, [at 9, at 10]) `shouldBe` Nothing
    ]
  where
    ctr = 1000
    resync w submitted = resynchronize SHA1 OTP6 w otpKey ctr submitted
    -- the value the client would show at the counter n ahead of the server's
    at n = hotp SHA1 OTP6 otpKey (ctr + n)
    -- the server counter n ahead of where it started
    serverAfter n = Just (ctr + n)
    wrongAt i vs = [if j == i then v + 1 else v | (j, v) <- zip [0 :: Int ..] vs]

-- | totpVerify accepts a value from any step within the skew window and
-- nothing else.  It compares a submitted value against secret-derived ones, so
-- pin the accepted and rejected cases down before that comparison is rewritten.
verifyTests :: [Spec]
verifyTests =
    [ it "the value for the current step is accepted" $
        assertBool "expected acceptance" (verifyAt 0)
    , it "every step within the window is accepted" $
        assertBool "expected acceptance" (all verifyAt [-2 .. 2])
    , it "the step just outside the window is refused" $
        assertBool "expected refusal" (not (any verifyAt [-3, 3]))
    , it "a value no step produces is refused" $
        assertBool "expected refusal" $
            not (totpVerify params otpKey now (totp params otpKey now + 1))
    , it "a window of no skew accepts only the current step" $
        assertBool "expected only the current step" $
            let noSkew = TOTP.mkTOTPParams SHA1 0 30 OTP6 NoSkew
             in case noSkew of
                    Left e -> error e
                    Right ps ->
                        totpVerify ps otpKey now (totp ps otpKey now)
                            && not (totpVerify ps otpKey now (totp ps otpKey (now + 30)))
    ]
  where
    params = defaultTOTPParams
    now = 1111111109

    -- one step is 30 seconds under defaultTOTPParams.  The offset is taken as
    -- an Integer so a step before the current one is an actual subtraction
    -- rather than a wrap around OTPTime, which is a Word64.
    verifyAt :: Integer -> Bool
    verifyAt steps =
        totpVerify params otpKey now (totp params otpKey (at steps))
    at steps = fromInteger (toInteger now + 30 * steps)

spec :: Spec
spec = do
    describe "HOTP" $ do
        describe "KATs" $ sequence_ (makeKATs (hotp SHA1 OTP6 otpKey) hotpExpected)
        describe "digest size" $ sequence_ digestSizeTests
        describe "resynchronize" $ sequence_ resyncTests
        describe "properties" $ do
            prop "resync-expected" prop_resyncExpected
    describe "TOTP" $ do
        describe "KATs" $ do
            describe "SHA1" $
                sequence_ (makeKATs (totp totpSHA1Params otpKey) totpSHA1Expected)
            describe "SHA256" $
                sequence_ $
                    (makeKATs (totp totpSHA256Params totpSHA256Key) totpSHA256Expected)
            describe "SHA512" $
                sequence_ $
                    (makeKATs (totp totpSHA512Params totpSHA512Key) totpSHA512Expected)
        describe "verify" $ sequence_ verifyTests
