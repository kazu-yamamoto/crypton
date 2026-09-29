-- The public key half of the README table, through crypton's Haskell API,
-- which is where ECDSA and RSA live.  One operation per process, named on
-- the command line, so the three versions can be alternated.  Prints
-- microseconds per operation.
--
-- Every operation is run over a list of prepared, differing inputs and every
-- result is folded into a number that is checked before the time is printed,
-- so nothing can be hoisted out of the loop or dropped.
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE FlexibleContexts #-}
module Main (main) where

import Control.Exception (evaluate)
import Control.Monad (foldM, forM, replicateM)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.Proxy (Proxy (..))
import Data.Word (Word64)
import GHC.Clock (getMonotonicTimeNSec)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

import Crypto.ECC
import Crypto.Error
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA (generateBlinder)
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Crypto.Random (MonadRandom, drgNewSeed, seedFromInteger, withDRG)

-- | Fold any byte-bearing result down to a number, so the optimiser has to
-- keep it.
sinkOf :: BA.ByteArrayAccess b => b -> Word64
sinkOf = B.foldl' (\a w -> a * 31 + fromIntegral w) 1 . BA.convert

-- | Best of several rounds over @inputs@, microseconds per operation.
timeIt :: [a] -> (a -> Word64) -> IO Double
timeIt inputs f = do
    let n = length inputs
    ts <- forM [1 :: Int .. 6] $ \_ -> do
        t0 <- getMonotonicTimeNSec
        s <- foldM (\acc x -> evaluate (acc + f x)) 0 inputs
        t1 <- getMonotonicTimeNSec
        return (fromIntegral (t1 - t0) / 1000 / fromIntegral n :: Double, s)
    let sink = sum (map snd ts)
    if sink == 0
        then hPutStrLn stderr "sink is zero" >> exitFailure
        else return (minimum (map fst (drop 1 ts)))

-- | Deterministic generation, so every version sees the same keys.
gen :: (forall m. MonadRandom m => m a) -> a
gen act = fst (withDRG (drgNewSeed (seedFromInteger 20260925)) act)

nOps :: Int
nOps = 60

msgs :: [B.ByteString]
msgs = [B.pack (replicate 32 (fromIntegral i)) | i <- [1 .. nOps]]

main :: IO ()
main = do
    args <- getArgs
    let what = case args of (a : _) -> a; _ -> ""
    us <- case what of
        "x25519" -> do
            let pairs = gen (replicateM nOps ((,) <$> X25519.generateSecretKey <*> (X25519.toPublic <$> X25519.generateSecretKey)))
            timeIt pairs (\(sk, pk) -> sinkOf (X25519.dh pk sk))
        "x25519-keygen" -> do
            let sks = gen (replicateM nOps X25519.generateSecretKey)
            timeIt sks (\sk -> sinkOf (X25519.toPublic sk))
        "x25519-ecc" -> ecdhBench (Proxy :: Proxy Curve_X25519)
        "ecdh-p256" -> ecdhBench (Proxy :: Proxy Curve_P256R1)
        "ecdh-p384" -> ecdhBench (Proxy :: Proxy Curve_P384R1)
        "ed25519-sign" -> do
            let sk = gen Ed25519.generateSecretKey
                pk = Ed25519.toPublic sk
            timeIt msgs (\m -> sinkOf (Ed25519.sign sk pk m))
        "ed25519-topublic" -> do
            let sks = [gen Ed25519.generateSecretKey | _ <- msgs]
            timeIt sks (\sk -> sinkOf (Ed25519.toPublic sk))
        "ed25519-verify" -> do
            let sk = gen Ed25519.generateSecretKey
                pk = Ed25519.toPublic sk
                sigs = [(m, Ed25519.sign sk pk m) | m <- msgs]
            timeIt sigs (\(m, s) -> if Ed25519.verify pk m s then 1 else 0)
        "ecdsa-p256-sign" -> ecdsaSign (Proxy :: Proxy Curve_P256R1)
        "ecdsa-p256-verify" -> ecdsaVerify (Proxy :: Proxy Curve_P256R1)
        "ecdsa-p384-sign" -> ecdsaSign (Proxy :: Proxy Curve_P384R1)
        "ecdsa-p384-verify" -> ecdsaVerify (Proxy :: Proxy Curve_P384R1)
        "rsa-sign-blinded" -> do
            let (pub, priv) = gen (RSA.generate 256 65537)
                blinders = gen (replicateM nOps (RSA.generateBlinder (RSA.public_n pub)))
            timeIt (zip blinders msgs) $ \(b, m) ->
                case PKCS15.sign (Just b) (Just SHA256) priv m of
                    Left _ -> 0
                    Right s' -> sinkOf s'
        "rsa-sign" -> do
            let (pub, priv) = gen (RSA.generate 256 65537)
            _ <- evaluate pub
            timeIt msgs $ \m ->
                case PKCS15.sign Nothing (Just SHA256) priv m of
                    Left _ -> 0
                    Right s -> sinkOf s
        "rsa-verify" -> do
            let (pub, priv) = gen (RSA.generate 256 65537)
                sigs = [ (m, s)
                       | m <- msgs
                       , Right s <- [PKCS15.sign Nothing (Just SHA256) priv m]
                       ]
            timeIt sigs (\(m, s) -> if PKCS15.verify (Just SHA256) pub m s then 1 else 0)
        _ -> hPutStrLn stderr ("unknown operation " ++ show what) >> exitFailure
    putStrLn (show us)

ecdhBench :: EllipticCurveDH c => Proxy c -> IO Double
ecdhBench prx = do
    let pairs = gen (replicateM nOps ((,) <$> (keypairGetPrivate <$> curveGenerateKeyPair prx)
                                          <*> (keypairGetPublic <$> curveGenerateKeyPair prx)))
    timeIt pairs $ \(s, p) ->
        case ecdh prx s p of
            CryptoPassed ss -> sinkOf ss
            CryptoFailed _ -> 0

ecdsaSign :: ECDSA.EllipticCurveECDSA c => Proxy c -> IO Double
ecdsaSign prx = do
    let priv = gen (keypairGetPrivate <$> curveGenerateKeyPair prx)
        ks = gen (replicateM nOps (curveGenerateScalar prx))
    timeIt (zip ks msgs) $ \(k, m) ->
        case ECDSA.signWith prx k priv SHA256 m of
            Nothing -> 0
            Just s -> let (r, sv) = ECDSA.signatureToIntegers prx s in fromIntegral (r + sv)

ecdsaVerify :: ECDSA.EllipticCurveECDSA c => Proxy c -> IO Double
ecdsaVerify prx = do
    let priv = gen (keypairGetPrivate <$> curveGenerateKeyPair prx)
        pub = ECDSA.toPublic prx priv
        ks = gen (replicateM nOps (curveGenerateScalar prx))
        sigs = [ (m, s)
               | (k, m) <- zip ks msgs
               , Just s <- [ECDSA.signWith prx k priv SHA256 m]
               ]
    timeIt sigs (\(m, s) -> if ECDSA.verify prx SHA256 pub s m then 1 else 0)
