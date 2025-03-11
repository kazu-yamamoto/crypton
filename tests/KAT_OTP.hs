{-# LANGUAGE OverloadedStrings #-}

module KAT_OTP (
    tests,
)
where

import Crypto.Hash.Algorithms (SHA1 (..), SHA256 (..), SHA512 (..))
import Crypto.OTP
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

makeKATs :: (Eq a, Show a) => (t -> a) -> [(t, a)] -> [TestTree]
makeKATs otp expected = concatMap (makeTest otp) (zip3 is counts otps)
  where
    is :: [Int]
    is = [1 ..]

    counts = map fst expected
    otps = map snd expected

makeTest :: (Eq a1, Show a2, Show a1) => (t -> a1) -> (a2, t, a1) -> [TestTree]
makeTest otp (i, count, password) =
    [ testCase (show i) (assertEqual "" password (otp count))
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

tests :: TestTree
tests =
    testGroup
        "OTP"
        [ testGroup
            "HOTP"
            [ testGroup "KATs" (makeKATs (hotp SHA1 OTP6 otpKey) hotpExpected)
            , testGroup
                "properties"
                [ testProperty "resync-expected" prop_resyncExpected
                ]
            ]
        , testGroup
            "TOTP"
            [ testGroup
                "KATs"
                [ testGroup "SHA1" (makeKATs (totp totpSHA1Params otpKey) totpSHA1Expected)
                , testGroup
                    "SHA256"
                    (makeKATs (totp totpSHA256Params totpSHA256Key) totpSHA256Expected)
                , testGroup
                    "SHA512"
                    (makeKATs (totp totpSHA512Params totpSHA512Key) totpSHA512Expected)
                ]
            ]
        ]
