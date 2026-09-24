{-# LANGUAGE ExistentialQuantification #-}
-- | A key's 'Show' instance is what a log, a crash report and a test
-- failure all reach for, and none of those is a place to put a private
-- key.  So the types that hold one do not print it, and the module below
-- holds them to that mechanically: the secret is rendered, and the
-- rendering must not appear in what 'show' returns.
module PubKey.SecrecySpec (spec) where

import Data.List (isInfixOf)

import Crypto.Debug (DebugShow, debugShow)
import Crypto.Error (CryptoFailable, throwCryptoError)
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.PubKey.Rabin.Basic as Basic
import qualified Crypto.PubKey.Rabin.Modified as Modified
import qualified Crypto.PubKey.Rabin.RW as RW

import qualified Data.ByteString as BS
import Data.Word (Word8)

import Imports

-- | Distinctive values, so that finding one in a rendering means it came
-- from the field it was put in and not from a coincidence of digits.
d1, d2, d3, d4, d5, d6 :: Integer
d1 = 0xd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1
d2 = 0xd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2
d3 = 0xd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3
d4 = 0xd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4
d5 = 0xd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5
d6 = 0xd6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6

rsaPub :: RSA.PublicKey
rsaPub = RSA.PublicKey{RSA.public_size = 32, RSA.public_n = 0xabc1, RSA.public_e = 0x10001}

rsaPriv :: RSA.PrivateKey
rsaPriv =
    RSA.PrivateKey
        { RSA.private_pub = rsaPub
        , RSA.private_d = d1
        , RSA.private_p = d2
        , RSA.private_q = d3
        , RSA.private_dP = d4
        , RSA.private_dQ = d5
        , RSA.private_qinv = d6
        }

dsaParams :: DSA.Params
dsaParams = DSA.Params{DSA.params_p = 0xabc2, DSA.params_g = 2, DSA.params_q = 0xabc3}

ecdsaCurve :: ECC.Curve
ecdsaCurve = ECC.getCurveByName ECC.SEC_p256r1

-- | Each entry names a value, what it renders to, and the secrets that
-- must not be findable in that rendering.
cases :: [(String, String, [Integer])]
cases =
    [ ("RSA.PrivateKey", show rsaPriv, [d1, d2, d3, d4, d5, d6])
    , ("RSA.KeyPair", show (RSA.KeyPair rsaPriv), [d1, d2, d3, d4, d5, d6])
    , ("DSA.PrivateKey", show (DSA.PrivateKey dsaParams d1), [d1])
    , ("DSA.KeyPair", show (DSA.KeyPair dsaParams 0xabc4 d1), [d1])
    , ("ECDSA.PrivateKey", show (ECDSA.PrivateKey ecdsaCurve d1), [d1])
    , ("ECDSA.KeyPair", show (ECDSA.KeyPair ecdsaCurve ECC.PointO d1), [d1])
    , ("DH.PrivateNumber", show (DH.PrivateNumber d1), [d1])
    ,
        ( "Rabin.Basic.PrivateKey"
        , show (Basic.PrivateKey (Basic.PublicKey 32 0xabc5) d1 d2 d3 d4)
        , [d1, d2, d3, d4]
        )
    ,
        ( "Rabin.Modified.PrivateKey"
        , show (Modified.PrivateKey (Modified.PublicKey 32 0xabc6) d1 d2 d3)
        , [d1, d2, d3]
        )
    ,
        ( "Rabin.RW.PrivateKey"
        , show (RW.PrivateKey (RW.PublicKey 32 0xabc7) d1 d2 d3)
        , [d1, d2, d3]
        )
    ]

-- | The values above again, paired with what 'debugShow' makes of them and
-- with a reading of that back, which has to give the value returned.
data Reveal = forall a. (Show a, Read a, Eq a, DebugShow a) => Reveal a

reveals :: [(String, Reveal, [Integer])]
reveals =
    [ ("RSA.PrivateKey", Reveal rsaPriv, [d1, d2, d3, d4, d5, d6])
    , ("RSA.KeyPair", Reveal (RSA.KeyPair rsaPriv), [d1, d2, d3, d4, d5, d6])
    , ("DSA.PrivateKey", Reveal (DSA.PrivateKey dsaParams d1), [d1])
    , ("DSA.KeyPair", Reveal (DSA.KeyPair dsaParams 0xabc4 d1), [d1])
    , ("ECDSA.PrivateKey", Reveal (ECDSA.PrivateKey ecdsaCurve d1), [d1])
    , ("ECDSA.KeyPair", Reveal (ECDSA.KeyPair ecdsaCurve ECC.PointO d1), [d1])
    , ("DH.PrivateNumber", Reveal (DH.PrivateNumber d1), [d1])
    ,
        ( "Rabin.Basic.PrivateKey"
        , Reveal (Basic.PrivateKey (Basic.PublicKey 32 0xabc5) d1 d2 d3 d4)
        , [d1, d2, d3, d4]
        )
    ,
        ( "Rabin.Modified.PrivateKey"
        , Reveal (Modified.PrivateKey (Modified.PublicKey 32 0xabc6) d1 d2 d3)
        , [d1, d2, d3]
        )
    ,
        ( "Rabin.RW.PrivateKey"
        , Reveal (RW.PrivateKey (RW.PublicKey 32 0xabc7) d1 d2 d3)
        , [d1, d2, d3]
        )
    ]

-- | The keys that keep their secret in a @ScrubbedBytes@.  Their 'Show' was
-- already silent; what is new is that 'debugShow' can speak.  The bytes are
-- distinct and not 0 or 255, so finding the hexadecimal of one in a rendering
-- means it came from the key.
scrubbed :: [(String, String, String, String)]
scrubbed =
    [ entry "Curve25519.SecretKey" 0x5a (X25519.secretKey . BS.replicate 32)
    , entry "Curve448.SecretKey" 0x5b (X448.secretKey . BS.replicate 56)
    , entry "Ed25519.SecretKey" 0x5c (Ed25519.secretKey . BS.replicate 32)
    , entry "Ed448.SecretKey" 0x5d (Ed448.secretKey . BS.replicate 57)
    ]
  where
    entry
        :: (Show k, DebugShow k)
        => String
        -> Word8
        -> (Word8 -> CryptoFailable k)
        -> (String, String, String, String)
    entry name b mk =
        let k = throwCryptoError (mk b)
         in (name, show k, debugShow k, hex b ++ hex b)
    hex :: Word8 -> String
    hex b = [digit (b `div` 16), digit (b `mod` 16)]
    digit n = "0123456789abcdef" !! fromIntegral n

spec :: Spec
spec = do
    describe "show does not print the secret" $ mapM_ check cases
    describe "debugShow does print the secret" $ mapM_ reveal reveals
    describe "debugShow round-trips through read" $ mapM_ roundTrip reveals
    describe "a scrubbed secret key" $ mapM_ scrub scrubbed
  where
    check (name, rendered, secrets) =
        it name $
            [s | s <- secrets, show s `isInfixOf` rendered] `shouldBe` []
    reveal (name, Reveal v, secrets) =
        it name $
            [s | s <- secrets, not (show s `isInfixOf` debugShow v)] `shouldBe` []
    roundTrip (name, Reveal v, _) =
        it name $ read (debugShow v) `shouldBe` v
    scrub (name, shown, revealed, h) = describe name $ do
        it "is not printed by show" $ (h `isInfixOf` shown) `shouldBe` False
        it "is printed by debugShow" $ (h `isInfixOf` revealed) `shouldBe` True
