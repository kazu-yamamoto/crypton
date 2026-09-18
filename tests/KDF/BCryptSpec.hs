{-# LANGUAGE OverloadedStrings #-}

module KDF.BCryptSpec (
    spec,
)
where

import Crypto.KDF.BCrypt
import qualified Data.ByteString as B
import Imports

-- Openwall bcrypt spec, with 2x versions and 0xFF special cases removed.
expected :: [(ByteString, ByteString)]
expected =
    [ ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U")
    , ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", "U*U*")
    , ("$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a", "U*U*U")
    ,
        ( "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"
        , "0123456789abcdefghijklmnopqrstuvwxyz\
          \ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\
          \chars after 72 are ignored"
        )
    , ("$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xff\xff\xa3")
    , ("$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xff\xff\xa3")
    , ("$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3")
    , ("$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3")
    , ("$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3")
    ,
        ( "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6"
        , "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
          \\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
          \\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
          \\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
          \\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
          \\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
          \chars after 72 are ignored as usual"
        )
    ,
        ( "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy"
        , "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
          \\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
          \\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
          \\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
          \\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\
          \\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
        )
    ,
        ( "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe"
        , "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
          \\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
          \\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
          \\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
          \\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\
          \\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
        )
    , ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy", "")
    , ("$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", "")
    , ("$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye", "")
    , ("$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW", "")
    , ("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO", "")
    , ("$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe", "a")
    , ("$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.", "a")
    , ("$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS", "a")
    , ("$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", "abc")
    , ("$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm", "abc")
    , ("$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi", "abc")
    ,
        ( "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"
        , "abcdefghijklmnopqrstuvwxyz"
        )
    ]

makeKATs = concatMap maketest (zip3 is passwords hashes)
  where
    is :: [Int]
    is = [1 ..]

    passwords = map snd expected
    hashes = map fst expected

    maketest (i, password, hash) =
        [ it (show i) (assertBool "" (validatePassword password hash))
        ]

spec :: Spec
spec = do
    describe "KATs" $ sequence_ makeKATs
    it
        "Invalid hash length"
        ( assertEqual
            ""
            (Left "Invalid hash format")
            ( validatePasswordEither
                B.empty
                ("$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s" :: B.ByteString)
            )
        )
    it
        "Hash and validate"
        ( assertBool
            "Hashed password should validate"
            (validatePassword somePassword (bcrypt 5 aSalt somePassword :: B.ByteString))
        )
    describe "password length limit" $ do
        -- bcrypt keys Blowfish with at most the first 72 bytes of the
        -- password, so everything after that is ignored.  The Openwall
        -- vectors above cover the hash value; these cover what it means for
        -- a caller, which is what the haddock now documents.
        it "ignores everything after the first 72 bytes" $
            bcrypt 5 aSalt longer `shouldBe` (bcrypt 5 aSalt otherTail :: B.ByteString)
        it "accepts a password differing only past the 72nd byte" $
            validatePassword otherTail (bcrypt 5 aSalt longer :: B.ByteString)
                `shouldBe` True
        it "still separates passwords differing within the first 72 bytes" $
            validatePassword
                (B.snoc (B.take 71 prefix72) 0x21)
                (bcrypt 5 aSalt longer :: B.ByteString)
                `shouldBe` False
  where
    prefix72 = B.replicate 72 0x61
    longer = prefix72 `B.append` "aaaaaaaaaaaaaaaaaaaa"
    otherTail = prefix72 `B.append` "something else entirely"
    somePassword = "some password" :: B.ByteString
    aSalt =
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
            :: B.ByteString
