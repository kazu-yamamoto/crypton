{-# LANGUAGE OverloadedStrings #-}

module KDF.Argon2Spec (spec) where

import Control.Exception (SomeException, evaluate, try)
import Crypto.Error
import qualified Crypto.KDF.Argon2 as Argon2
import qualified Data.ByteString as B
import Imports

data KDFVector = KDFVector
    { kdfPass :: ByteString
    , kdfSalt :: ByteString
    , kdfOptions :: Argon2.Options
    , kdfResult :: ByteString
    }

argon2i_13 :: Argon2.TimeCost -> Argon2.MemoryCost -> Argon2.Options
argon2i_13 iters memory =
    Argon2.Options
        { Argon2.iterations = iters
        , Argon2.memory = memory
        , Argon2.parallelism = 1
        , Argon2.variant = Argon2.Argon2i
        , Argon2.version = Argon2.Version13
        }

vectors =
    [ KDFVector
        "password"
        "somesalt"
        (argon2i_13 2 65536)
        "\xc1\x62\x88\x32\x14\x7d\x97\x20\xc5\xbd\x1c\xfd\x61\x36\x70\x78\x72\x9f\x6d\xfb\x6f\x8f\xea\x9f\xf9\x81\x58\xe0\xd7\x81\x6e\xd0"
    ]

kdfTests :: [Spec]
kdfTests = zipWith toKDFTest is vectors
  where
    toKDFTest i v =
        it
            (show i)
            ( Argon2.hash (kdfOptions v) (kdfPass v) (kdfSalt v) (B.length $ kdfResult v)
                `shouldBe` CryptoPassed (kdfResult v)
            )

    is :: [Int]
    is = [1 ..]

-- | 'Argon2.hash' returns a 'CryptoFailable', but the bounds on iterations,
-- memory and parallelism are only enforced by the C implementation, whose
-- return code was turned into an 'error' raised from inside the allocation.
-- Invalid options have to come back through the failure the type already
-- offers.
--
-- The result is forced, because 'CryptoPassed' holds the bytes lazily and the
-- raise happens when they are produced.
outcome
    :: CryptoFailable ByteString
    -> IO (Either String (Either CryptoError Int))
outcome r = do
    result <- try (evaluate (forceResult r))
    return $ either (Left . takeWhile (/= '\n') . showExc) Right result
  where
    forceResult (CryptoFailed err) = Left err
    forceResult (CryptoPassed bs) = Right $! B.length bs

    showExc :: SomeException -> String
    showExc = show

refuses :: String -> Argon2.Options -> Spec
refuses name options = it name $ do
    result <- outcome (Argon2.hash options pass salt outLen)
    case result of
        Left e -> assertFailure ("raised instead of failing: " ++ e)
        Right (Right n) -> assertFailure ("unexpectedly produced " ++ show n ++ " bytes")
        Right (Left _) -> return ()

pass :: ByteString
pass = "password"

salt :: ByteString
salt = "somesalt"

outLen :: Int
outLen = 32

optionTests :: [Spec]
optionTests =
    [ it "valid options hash" $ do
        result <- outcome (Argon2.hash (argon2i_13 2 65536) pass salt outLen)
        result `shouldBe` Right (Right outLen)
    , refuses
        "parallelism of 0 is refused"
        (argon2i_13 2 65536){Argon2.parallelism = 0}
    , refuses "iterations of 0 is refused" (argon2i_13 0 65536)
    , refuses "memory below the minimum is refused" (argon2i_13 2 1)
    ]

spec :: Spec
spec = do
    describe "KATs" $ sequence_ kdfTests
    describe "options" $ sequence_ optionTests
