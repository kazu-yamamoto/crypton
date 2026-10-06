{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | ML-KEM against NIST's ACVP vectors, and against itself.
--
-- The vectors are the point: a round trip only says the two halves of one
-- implementation agree with each other, which they would even if both were
-- wrong in the same way.
module PubKey.MLKEMSpec (spec) where

import qualified Data.ByteArray as B
import Data.ByteArray.Encoding (Base (Base16), convertFromBase)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Data.Proxy (Proxy (..))
import Test.Hspec
import Test.Hspec.QuickCheck (prop)

import Crypto.Error
import Crypto.PubKey.MLKEM

import Imports ()
import PubKey.MLKEMVectors

hex :: String -> BS.ByteString
hex s = case convertFromBase Base16 (BS.pack (map (fromIntegral . fromEnum) s)) of
    Left e -> error ("bad hex in a test vector: " ++ e)
    Right b -> b

-- | Run an action for whichever parameter set a vector names.  The set is a
-- type, so there is no way to pass it as a value; this is the one place that
-- turns the name back into one.
withSet
    :: String
    -> (forall p. MLKEM p => Proxy p -> r)
    -> r
withSet "ML-KEM-512" k = k (Proxy :: Proxy MLKEM512)
withSet "ML-KEM-768" k = k (Proxy :: Proxy MLKEM768)
withSet "ML-KEM-1024" k = k (Proxy :: Proxy MLKEM1024)
withSet s _ = error ("unknown parameter set in a test vector: " ++ s)

spec :: Spec
spec = do
    describe "ACVP keyGen" $
        mapM_ keyGenCase keyGenVectors
    describe "ACVP encapsulation" $
        mapM_ encapCase encapVectors
    describe "ACVP decapsulation" $
        mapM_ decapCase decapVectors
    describe "ACVP encapsulation key check (FIPS 203 7.2)" $
        mapM_ (checkCase "encapsulation key" encapsulationKeyOf) ekCheckVectors
    describe "ACVP decapsulation key check (FIPS 203 7.3)" $
        mapM_ (checkCase "decapsulation key" decapsulationKeyOf) dkCheckVectors
    describe "the seed a key pair came from" $ do
        seedKeeps "ML-KEM-512" (Proxy :: Proxy MLKEM512)
        seedKeeps "ML-KEM-768" (Proxy :: Proxy MLKEM768)
        seedKeeps "ML-KEM-1024" (Proxy :: Proxy MLKEM1024)
    describe "round trip" $ do
        roundTrip "ML-KEM-512" (Proxy :: Proxy MLKEM512)
        roundTrip "ML-KEM-768" (Proxy :: Proxy MLKEM768)
        roundTrip "ML-KEM-1024" (Proxy :: Proxy MLKEM1024)
    describe "a ciphertext that was not meant for this key" $ do
        implicitRejection "ML-KEM-512" (Proxy :: Proxy MLKEM512)
        implicitRejection "ML-KEM-768" (Proxy :: Proxy MLKEM768)
        implicitRejection "ML-KEM-1024" (Proxy :: Proxy MLKEM1024)

keyGenCase :: KeyGenVector -> Spec
keyGenCase v =
    it (kgSet v ++ " tcId " ++ show (kgId v)) $
        withSet (kgSet v) $ \p ->
            case keyPairFromSeed p (hex (kgD v) `BS.append` hex (kgZ v)) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed (ek, dk) -> do
                    B.convert ek `shouldBe` hex (kgEk v)
                    B.convert dk `shouldBe` hex (kgDk v)

encapCase :: EncapVector -> Spec
encapCase v =
    it (enSet v ++ " tcId " ++ show (enId v)) $
        withSet (enSet v) $ \(p :: Proxy p) ->
            case encapsulationKey (hex (enEk v)) :: CryptoFailable (EncapsulationKey p) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed ek -> case encapsulateWith p ek (B.convert (hex (enM v))) of
                    CryptoFailed e -> expectationFailure (show e)
                    CryptoPassed (ct, ss) -> do
                        B.convert ct `shouldBe` hex (enC v)
                        B.convert ss `shouldBe` hex (enK v)

decapCase :: DecapVector -> Spec
decapCase v =
    it (deSet v ++ " tcId " ++ show (deId v)) $
        withSet (deSet v) $ \(p :: Proxy p) ->
            case ( decapsulationKey (hex (deDk v)) :: CryptoFailable (DecapsulationKey p)
                 , ciphertext (hex (deC v)) :: CryptoFailable (Ciphertext p)
                 ) of
                (CryptoPassed dk, CryptoPassed ct) ->
                    case decapsulate p dk ct of
                        CryptoPassed ss -> B.convert ss `shouldBe` hex (deK v)
                        CryptoFailed e -> expectationFailure (show e)
                (CryptoFailed e, _) -> expectationFailure (show e)
                (_, CryptoFailed e) -> expectationFailure (show e)

-- | The two key checks, each given a key the vector says to accept and one it
-- says to refuse.  A constructor that accepted everything would pass the
-- first and fail the second.
checkCase
    :: String
    -> (forall p. MLKEM p => Proxy p -> BS.ByteString -> Bool)
    -> KeyCheckVector
    -> Spec
checkCase what accepts v =
    it (ckSet v ++ " tcId " ++ show (ckId v) ++ verdict) $
        withSet (ckSet v) (\p -> accepts p (hex (ckKey v))) `shouldBe` ckPasses v
  where
    verdict
        | ckPasses v = " (a sound " ++ what ++ ")"
        | otherwise = " (" ++ what ++ " the standard refuses)"

encapsulationKeyOf :: MLKEM p => Proxy p -> BS.ByteString -> Bool
encapsulationKeyOf (_ :: Proxy p) bs =
    case encapsulationKey bs :: CryptoFailable (EncapsulationKey p) of
        CryptoPassed _ -> True
        CryptoFailed _ -> False

decapsulationKeyOf :: MLKEM p => Proxy p -> BS.ByteString -> Bool
decapsulationKeyOf (_ :: Proxy p) bs =
    case decapsulationKey bs :: CryptoFailable (DecapsulationKey p) of
        CryptoPassed _ -> True
        CryptoFailed _ -> False

-- The seed and the coins are drawn as lists of bytes and padded to the
-- lengths the entry points want; there is no Arbitrary ByteString in scope
-- and one is not worth adding for this.
-- The seed generateKeyPairAndSeed hands back has to be the one the pair
-- was derived from: expanding it again has to give that very pair, not
-- merely some pair.  Two generated pairs also have to differ.
seedKeeps :: MLKEM p => String -> Proxy p -> Spec
seedKeeps name p =
    it (name ++ ": the seed comes back and rebuilds the pair") $ do
        (ek, dk, seed) <- generateKeyPairAndSeed p
        B.length seed `shouldBe` seedSize
        case keyPairFromSeed p seed of
            CryptoPassed (ek', dk') -> do
                (B.convert ek' :: BS.ByteString) `shouldBe` B.convert ek
                (B.convert dk' :: BS.ByteString) `shouldBe` B.convert dk
            CryptoFailed e -> expectationFailure (show e)
        (ek2, _, _) <- generateKeyPairAndSeed p
        (B.convert ek2 :: BS.ByteString) `shouldNotBe` B.convert ek

roundTrip :: MLKEM p => String -> Proxy p -> Spec
roundTrip name p =
    prop (name ++ ": the two sides agree") $ \(seedBytes :: [Word8]) coinBytes ->
        let pad n bs = BS.take n (bs `BS.append` BS.replicate n 0)
            d = pad 64 (BS.pack seedBytes)
            m = pad 32 (BS.pack coinBytes)
         in case keyPairFromSeed p d of
                CryptoFailed e -> error (show e)
                CryptoPassed (ek, dk) -> case encapsulateWith p ek (B.convert m) of
                    CryptoFailed e -> error (show e)
                    CryptoPassed (ct, ss) ->
                        (B.convert <$> decapsulate p dk ct)
                            == CryptoPassed (B.convert ss :: BS.ByteString)

-- | Decapsulating a ciphertext made for a different key answers something,
-- and that something is not the other key pair's secret.  ML-KEM rejects
-- implicitly, so there is no error to look for -- only a secret that does not
-- match, which is what a caller would see.
implicitRejection :: MLKEM p => String -> Proxy p -> Spec
implicitRejection name p =
    it (name ++ ": answers a secret that does not match") $ do
        let seedA = BS.replicate 64 7
            seedB = BS.replicate 64 9
            m = BS.replicate 32 3
        case (keyPairFromSeed p seedA, keyPairFromSeed p seedB) of
            (CryptoPassed (ekA, _), CryptoPassed (_, dkB)) ->
                case encapsulateWith p ekA (B.convert m) of
                    CryptoPassed (ct, ss) ->
                        case decapsulate p dkB ct of
                            CryptoPassed ss' ->
                                (B.convert ss' :: BS.ByteString)
                                    `shouldNotBe` B.convert ss
                            CryptoFailed e -> expectationFailure (show e)
                    CryptoFailed e -> expectationFailure (show e)
            _ -> expectationFailure "could not derive the two key pairs"
