{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | ML-DSA against NIST's ACVP vectors, and against itself.
--
-- The vectors are the point.  A signature this module makes and then verifies
-- says only that its two halves agree; the vectors say the signature is the
-- one FIPS 204 asks for, which is what a peer will check it against.
module PubKey.MLDSASpec (spec) where

import qualified Data.ByteArray as B
import Data.ByteArray.Encoding (Base (Base16), convertFromBase)
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import Control.Monad (forM_, when)
import Data.List (nub)
import Test.Hspec hiding (context)

import Crypto.Error
import Crypto.PubKey.MLDSA

import Imports ()
import PubKey.MLDSAVectors

hex :: String -> BS.ByteString
hex s = case convertFromBase Base16 (BS.pack (map (fromIntegral . fromEnum) s)) of
    Left e -> error ("bad hex in a test vector: " ++ e)
    Right b -> b

withSet :: String -> (forall p. MLDSA p => Proxy p -> r) -> r
withSet "ML-DSA-44" k = k (Proxy :: Proxy MLDSA44)
withSet "ML-DSA-65" k = k (Proxy :: Proxy MLDSA65)
withSet "ML-DSA-87" k = k (Proxy :: Proxy MLDSA87)
withSet s _ = error ("unknown parameter set in a test vector: " ++ s)

ctxOf :: String -> Context
ctxOf "" = emptyContext
ctxOf s = case context (hex s) of
    CryptoPassed c -> c
    CryptoFailed e -> error (show e)

spec :: Spec
spec = do
    describe "ACVP keyGen" $
        mapM_ keyGenCase keyGenVectors
    describe "ACVP sigGen" $
        mapM_ sigGenCase sigGenVectors
    describe "what a signature is bound to" $
        mapM_ bindingCase sigGenVectors
    describe "ACVP sigGen, the external-mu interface" $
        mapM_ extMuCase extMuVectors
    describe "the message representative" $
        mapM_ muCase sigGenVectors
    describe "the message representative, a piece at a time" $
        mapM_ muStreamCase sigGenVectors
    describe "the seed a key pair came from" $ do
        seedKeeps "ML-DSA-44" (Proxy :: Proxy MLDSA44)
        seedKeeps "ML-DSA-65" (Proxy :: Proxy MLDSA65)
        seedKeeps "ML-DSA-87" (Proxy :: Proxy MLDSA87)
    describe "round trip" $ do
        roundTrip "ML-DSA-44" (Proxy :: Proxy MLDSA44)
        roundTrip "ML-DSA-65" (Proxy :: Proxy MLDSA65)
        roundTrip "ML-DSA-87" (Proxy :: Proxy MLDSA87)

keyGenCase :: KeyGenVector -> Spec
keyGenCase v =
    it (kgSet v ++ " tcId " ++ show (kgId v)) $
        withSet (kgSet v) $ \p ->
            case keyPairFromSeed p (hex (kgSeed v)) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed (vk, sk) -> do
                    B.convert vk `shouldBe` hex (kgPk v)
                    B.convert sk `shouldBe` hex (kgSk v)

sigGenCase :: SigGenVector -> Spec
sigGenCase v =
    it (label v) $
        withSet (sgSet v) $ \(_ :: Proxy p) ->
            case signingKey (hex (sgSk v)) :: CryptoFailable (SigningKey p) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed sk ->
                    let ctx = ctxOf (sgContext v)
                        msg = hex (sgMessage v)
                        got
                            | sgDeterministic v =
                                CryptoPassed (signDeterministic sk ctx msg)
                            | otherwise = signWith sk ctx msg (hex (sgRnd v))
                     in case got of
                            CryptoFailed e -> expectationFailure (show e)
                            CryptoPassed s ->
                                B.convert s `shouldBe` hex (sgSignature v)

-- | The vector's own signature, verified -- and then the three ways it should
-- stop verifying.  Signing and verifying with this module alone could agree
-- on a wrong domain prefix; this pins the prefix to the vector's signature
-- and then shows the context is really part of it.
bindingCase :: SigGenVector -> Spec
bindingCase v =
    it (label v) $
        withSet (sgSet v) $ \(_ :: Proxy p) ->
            case ( signingKey (hex (sgSk v)) :: CryptoFailable (SigningKey p)
                 , signature (hex (sgSignature v)) :: CryptoFailable (Signature p)
                 ) of
                (CryptoPassed sk, CryptoPassed sig) -> do
                    let vk = toPublic sk
                        ctx = ctxOf (sgContext v)
                        msg = hex (sgMessage v)
                    verify vk ctx msg sig `shouldBe` True
                    verify vk ctx (flipFirst msg) sig `shouldBe` False
                    verify vk (otherContext (sgContext v)) msg sig `shouldBe` False
                    case signature (flipFirst (hex (sgSignature v))) of
                        CryptoPassed bad -> verify vk ctx msg bad `shouldBe` False
                        CryptoFailed e -> expectationFailure (show e)
                (CryptoFailed e, _) -> expectationFailure (show e)
                (_, CryptoFailed e) -> expectationFailure (show e)
  where
    flipFirst b
        | BS.null b = BS.singleton 1
        | otherwise = BS.cons (BS.head b `seq` BS.head b + 1) (BS.tail b)
    -- any context other than the one it was signed under
    otherContext "" = ctxOf "00"
    otherContext _ = emptyContext

-- Signing a representative the vector supplies.
extMuCase :: ExtMuVector -> Spec
extMuCase v =
    it (xmSet v ++ " tcId " ++ show (xmId v) ++ det) $
        withSet (xmSet v) $ \(_ :: Proxy p) ->
            case ( signingKey (hex (xmSk v)) :: CryptoFailable (SigningKey p)
                 , mu (hex (xmMu v))
                 ) of
                (CryptoPassed sk, CryptoPassed m) -> do
                    let got
                            | xmDeterministic v =
                                CryptoPassed (signExternalMuDeterministic sk m)
                            | otherwise = signExternalMuWith sk m (hex (xmRnd v))
                    case got of
                        CryptoFailed e -> expectationFailure (show e)
                        CryptoPassed sig -> do
                            B.convert sig `shouldBe` hex (xmSignature v)
                            verifyExternalMu (toPublic sk) m sig `shouldBe` True
                (CryptoFailed e, _) -> expectationFailure (show e)
                (_, CryptoFailed e) -> expectationFailure (show e)
  where
    det = if xmDeterministic v then ", deterministic" else ", hedged"

-- messageRepresentative, against a vector that never mentions mu.
--
-- The vectors for the external-mu interface supply the representative, so
-- using them would only say that signing it works, not that this computes
-- the right one.  Taking a vector from the ordinary interface and computing
-- the representative from its key, context and message does say that: the
-- signature has to come out the same as the one the vector gives for
-- signing that message directly.
muCase :: SigGenVector -> Spec
muCase v =
    it (label v) $
        withSet (sgSet v) $ \(_ :: Proxy p) ->
            case signingKey (hex (sgSk v)) :: CryptoFailable (SigningKey p) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed sk -> do
                    let vk = toPublic sk
                        ctx = ctxOf (sgContext v)
                        msg = hex (sgMessage v)
                        m = messageRepresentative vk ctx msg
                    B.length m `shouldBe` muSize
                    let viaMu = B.convert (signExternalMuDeterministic sk m)
                        direct = B.convert (signDeterministic sk ctx msg)
                    (viaMu :: BS.ByteString) `shouldBe` direct
                    -- and for the deterministic vectors it is the
                    -- signature the vector itself gives
                    when (sgDeterministic v) $
                        viaMu `shouldBe` hex (sgSignature v)

-- The streaming form, against the same vectors.
--
-- Where the message is cut must not matter, so every cut is tried: none,
-- at the front, at the back, at thirds, and one byte at a time.  All of
-- them have to give what 'messageRepresentative' gives for the whole
-- message, and -- for the deterministic vectors -- signing that has to
-- give the signature the vector itself holds.  Without that last step the
-- test would only say two of this module's paths agree with each other.
muStreamCase :: SigGenVector -> Spec
muStreamCase v =
    it (label v) $
        withSet (sgSet v) $ \(_ :: Proxy p) ->
            case signingKey (hex (sgSk v)) :: CryptoFailable (SigningKey p) of
                CryptoFailed e -> expectationFailure (show e)
                CryptoPassed sk -> do
                    let vk = toPublic sk
                        ctx = ctxOf (sgContext v)
                        msg = hex (sgMessage v)
                        whole = B.convert (messageRepresentative vk ctx msg)
                        n = BS.length msg
                        cuts = nub [0, 1, n `div` 3, n `div` 2, n - 1, n]
                        chunked :: [BS.ByteString] -> BS.ByteString
                        chunked cs =
                            B.convert (muFinalize (muUpdates (muInit vk ctx) cs))
                    forM_ (filter (\i -> i >= 0 && i <= n) cuts) $ \i ->
                        let (a, b) = BS.splitAt i msg
                         in chunked [a, b] `shouldBe` (whole :: BS.ByteString)
                    chunked (map BS.singleton (BS.unpack msg))
                        `shouldBe` (whole :: BS.ByteString)
                    -- an empty piece is not a piece
                    chunked [BS.empty, msg, BS.empty]
                        `shouldBe` (whole :: BS.ByteString)
                    let streamed =
                            muFinalize $
                                muUpdate (muUpdate (muInit vk ctx) (BS.take 1 msg)) $
                                    BS.drop 1 msg
                    when (sgDeterministic v) $
                        (B.convert (signExternalMuDeterministic sk streamed) :: BS.ByteString)
                            `shouldBe` hex (sgSignature v)

-- The seed generateKeyPairAndSeed hands back has to be the one the pair
-- was derived from: expanding it again has to give that very pair, not
-- merely some pair.  Two generated pairs also have to differ.
seedKeeps :: MLDSA p => String -> Proxy p -> Spec
seedKeeps name p =
    it (name ++ ": the seed comes back and rebuilds the pair") $ do
        (vk, sk, seed) <- generateKeyPairAndSeed p
        B.length seed `shouldBe` seedSize
        case keyPairFromSeed p seed of
            CryptoPassed (vk', sk') -> do
                (B.convert vk' :: BS.ByteString) `shouldBe` B.convert vk
                (B.convert sk' :: BS.ByteString) `shouldBe` B.convert sk
            CryptoFailed e -> expectationFailure (show e)
        (vk2, _, _) <- generateKeyPairAndSeed p
        (B.convert vk2 :: BS.ByteString) `shouldNotBe` B.convert vk

roundTrip :: MLDSA p => String -> Proxy p -> Spec
roundTrip name p =
    it (name ++ ": a signature this module makes, it verifies") $
        case keyPairFromSeed p (BS.replicate 32 5) of
            CryptoFailed e -> expectationFailure (show e)
            CryptoPassed (vk, sk) -> do
                let msg = BS.pack [1 .. 40]
                    ctx = ctxOf "aabb"
                    sig = signDeterministic sk ctx msg
                verify vk ctx msg sig `shouldBe` True
                toPublic sk `shouldBe` vk
                -- the same key and message twice give the same signature
                signDeterministic sk ctx msg `shouldBe` sig

label :: SigGenVector -> String
label v =
    sgSet v
        ++ " tcId "
        ++ show (sgId v)
        ++ (if sgDeterministic v then ", deterministic" else ", hedged")
        ++ (if null (sgContext v) then ", no context" else ", with a context")
