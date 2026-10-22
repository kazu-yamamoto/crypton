-- expFast with e = 65537 at each RSA size: whichever path the build takes.
import Control.Exception (evaluate)
import Control.Monad (foldM, forM, forM_)
import Data.Bits (setBit, shiftL)
import Data.Word (Word64)
import GHC.Clock (getMonotonicTimeNSec)
import Crypto.Number.ModArithmetic (expFast)

lcg :: Integer -> Integer
lcg x = (x * 6364136223846793005 + 1442695040888963407) `mod` (2 ^ (64 :: Int))

rand :: Int -> Integer -> Integer
rand bits seed = foldr (\w a -> a `shiftL` 64 + w) 0 (take (bits `div` 64) (tail (iterate lcg seed)))

main :: IO ()
main = forM_ [1024, 1536, 2048, 3072, 4096] $ \bits -> do
    let n = rand bits 7 `setBit` 0 `setBit` (bits - 1)
        cs = [rand bits (fromIntegral i) `mod` n | i <- [100 .. 159 :: Int]]
    _ <- evaluate (sum cs)
    _ <- evaluate (expFast (head cs) 65537 n)
    ts <- forM [1 :: Int .. 9] $ \_ -> do
        t0 <- getMonotonicTimeNSec
        s <- foldM (\a c -> evaluate (a + fromIntegral (expFast c 65537 n) :: Word64)) 0 cs
        t1 <- getMonotonicTimeNSec
        return (fromIntegral (t1 - t0) / 1000 / 60 :: Double, s)
    _ <- evaluate (sum (map snd ts))
    putStrLn (show bits ++ "\t" ++ show (minimum (map fst (drop 1 ts))))
