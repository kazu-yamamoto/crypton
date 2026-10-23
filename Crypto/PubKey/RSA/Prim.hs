{-# LANGUAGE BangPatterns #-}

-- |
-- Module      : Crypto.PubKey.RSA.Prim
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.PubKey.RSA.Prim (
    -- * Decrypt primitive
    dp,

    -- * Encrypt primitive
    ep,
) where

import Data.Memory.PtrMethods (memSet)
import Data.Word (Word32, Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, plusPtr)

import Crypto.Internal.ByteArray (ByteArray)
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Number.Basic (numBytes)
import Crypto.Number.ModArithmetic (expFast, expSafe)
import Crypto.Number.ModArithmetic.Pub (expPubBytes)
import Crypto.Number.Serialize (i2ospOf_, os2ip)
import qualified Crypto.Number.Serialize.Internal as Internal
import Crypto.PubKey.RSA.Types

{- dpSlow computes the decrypted message not using any precomputed cache value.
   only n and d need to valid. -}
dpSlow :: ByteArray ba => PrivateKey -> ba -> ba
dpSlow pk c = i2ospOf_ (private_size pk) $ expSafe (os2ip c) (private_d pk) (private_n pk)

{- dpFast computes the decrypted message more efficiently if the
   precomputed private values are available. mod p and mod q are faster
   to compute than mod pq -}
dpFast :: ByteArray ba => Blinder -> PrivateKey -> ba -> ba
dpFast (Blinder r rm1) pk c =
    i2ospOf_
        (private_size pk)
        (multiplication rm1 (crtChecked pk iC (m2 + h * (private_q pk))) (private_n pk))
  where
    re = expFast r (public_e $ private_pub pk) (private_n pk)
    iC = multiplication re (os2ip c) (private_n pk)
    (m1, m2) = crtHalves iC pk
    h = ((private_qinv pk) * (m1 - m2)) `mod` (private_p pk)

dpFastNoBlinder :: ByteArray ba => PrivateKey -> ba -> ba
dpFastNoBlinder pk c = i2ospOf_ (private_size pk) (crtChecked pk iC (m2 + h * (private_q pk)))
  where
    iC = os2ip c
    (m1, m2) = crtHalves iC pk
    h = ((private_qinv pk) * (m1 - m2)) `mod` (private_p pk)

-- | The CRT answer m for c, raised back to e before it is let out: a fault
-- in one half gives an m whose gcd with n is the other prime (Boneh, DeMillo
-- and Lipton).  On a mismatch it is computed again without CRT, as OpenSSL does.
crtChecked :: PrivateKey -> Integer -> Integer -> Integer
crtChecked pk c m
    | expFast m (public_e (private_pub pk)) n == c `mod` n = m
    | private_d pk > 0 = expSafe c (private_d pk) n
    | otherwise = m
  where
    n = private_n pk

-- | c^dP mod p and c^dQ mod q, the halves of the private-key operation: both
-- at once where the C can (AVX-512 IFMA, and the sizes of RSA-2048, -3072 and
-- -4096), one after the other where it declines.
crtHalves :: Integer -> PrivateKey -> (Integer, Integer)
crtHalves c pk = case expSafeX2 (c `mod` p) dP p (c `mod` q) dQ q of
    Just r -> r
    Nothing -> (expSafe c dP p, expSafe c dQ q)
  where
    p = private_p pk
    q = private_q pk
    dP = private_dP pk
    dQ = private_dQ pk

-- | Two secure exponentiations in one call.  The bases are reduced already
-- and the moduli are the same length; both exponents go in at that length,
-- so the length the C sees is the modulus', as 'expSafe' pads to whole words.
expSafeX2 :: Integer -> Integer -> Integer -> Integer -> Integer -> Integer -> Maybe (Integer, Integer)
expSafeX2 b1 e1 m1 b2 e2 m2
    | numBytes m2 /= len || not (odd m1 && odd m2) = Nothing
    | e1 < 0 || e2 < 0 || numBytes e1 > len || numBytes e2 > len = Nothing
    | otherwise = unsafeDoIO $
        allocaBytes (8 * len) $ \start -> case take 8 (iterate (`plusPtr` len) start) of
            [o1, pb1, pe1, pm1, o2, pb2, pe2, pm2] -> do
                mapM_
                    (\(v, ptr) -> Internal.i2ospOf v ptr len)
                    [(b1, pb1), (e1, pe1), (m1, pm1), (b2, pb2), (e2, pe2), (m2, pm2)]
                r <- c_powm_sec_x2 o1 pb1 l pe1 l pm1 l o2 pb2 l pe2 l pm2 l
                -- the exponents are the caller's secrets
                memSet pe1 0 len
                memSet pe2 0 len
                if r /= 0
                    then return Nothing
                    else do
                        !v1 <- Internal.os2ip o1 len
                        !v2 <- Internal.os2ip o2 len
                        return (Just (v1, v2))
            _ -> return Nothing
  where
    !len = numBytes m1
    l = fromIntegral len :: Word32

foreign import ccall safe "crypton_powm_sec_x2"
    c_powm_sec_x2
        :: Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32
        -> Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32
        -> IO CInt

-- | Compute the RSA decrypt primitive.
-- if the p and q numbers are available, then dpFast is used
-- otherwise, we use dpSlow which only need d and n.
dp :: ByteArray ba => Maybe Blinder -> PrivateKey -> ba -> ba
dp blinder pk
    | private_p pk /= 0 && private_q pk /= 0 =
        maybe dpFastNoBlinder dpFast blinder $ pk
    | otherwise = dpSlow pk

-- | Compute the RSA encrypt primitive
ep :: ByteArray ba => PublicKey -> ba -> ba
ep pk m = case expPubBytes (public_e pk) (public_n pk) m of
    Just r -> r
    Nothing -> i2ospOf_ (public_size pk) $ expFast (os2ip m) (public_e pk) (public_n pk)

-- | multiply 2 integers in Zm only performing the modulo operation if necessary
multiplication :: Integer -> Integer -> Integer -> Integer
multiplication a b m = (a * b) `mod` m
