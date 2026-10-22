{-# LANGUAGE BangPatterns #-}

-- |
-- Module      : Crypto.Number.ModArithmetic.Pub
-- License     : BSD-style
-- Stability   : experimental
-- Portability : Good
--
-- The C exponentiation for an exponent that is not a secret, and the R^2
-- it keeps per modulus.  Internal: 'expPub' is behind 'expFast', and
-- 'expPubBytes' behind RSA's public-key operation.
module Crypto.Number.ModArithmetic.Pub (
    expPub,
    expPubBytes,
) where

import Crypto.Internal.ByteArray (
    ByteArray,
    ByteArrayAccess,
    Bytes,
    allocRet,
    withByteArray,
 )
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Number.Basic
import qualified Crypto.Number.Serialize.Internal as Internal
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.Word (Word32, Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)

-- | The windowless exponentiation in C, for an exponent that is not a
--   secret.  'Nothing' when the C declines, which it does on every machine
--   where what the caller already has is faster -- so this is an
--   optimisation and never the only path.  The base has to be reduced and
--   the exponent positive, which the caller sees to.
expPub :: Integer -> Integer -> Integer -> Maybe Integer
expPub b e m = unsafeDoIO $ do
    known <- r2For m
    case known of
        Nothing -> return Nothing
        Just (r2, modu) ->
            allocaBytes (sum widths) $ \start -> case scanl plusPtr start widths of
                (out : base : expo : _) -> do
                    _ <- Internal.i2ospOf b base mLen
                    _ <- Internal.i2ospOf e expo eLen
                    r <- withByteArray modu $ \pm -> withByteArray r2 $ \pr2 ->
                        c_powm_pub_r2
                            out
                            base
                            (fromIntegral mLen)
                            expo
                            (fromIntegral eLen)
                            pm
                            (fromIntegral mLen)
                            pr2
                    if r == 0
                        then do
                            !v <- Internal.os2ip out mLen
                            return (Just v)
                        else return Nothing
                _ -> return Nothing
  where
    !mLen = numBytes m
    !eLen = numBytes e
    widths = [mLen, mLen, eLen]

-- | The same with the base and the answer as big-endian bytes, as long as
--   the modulus: what RSA verification has in hand, so neither goes through
--   an 'Integer'.  'Nothing' also when the base is not below the modulus.
expPubBytes
    :: (ByteArrayAccess bi, ByteArray bo) => Integer -> Integer -> bi -> Maybe bo
expPubBytes e m b
    | e <= 0 || m <= 1 || even m || B.length b /= mLen = Nothing
    | otherwise = unsafeDoIO $ do
        known <- r2For m
        case known of
            Nothing -> return Nothing
            Just (r2, modu)
                | not (below b modu) -> return Nothing
                | otherwise -> allocaBytes eLen $ \expo -> do
                    _ <- Internal.i2ospOf e expo eLen
                    (r, out) <- allocRet mLen $ \pout ->
                        withByteArray b $ \pb -> withByteArray modu $ \pm ->
                            withByteArray r2 $ \pr2 ->
                                c_powm_pub_r2
                                    pout
                                    pb
                                    (fromIntegral mLen)
                                    expo
                                    (fromIntegral eLen)
                                    pm
                                    (fromIntegral mLen)
                                    pr2
                    return (if r == 0 then Just out else Nothing)
  where
    !mLen = numBytes m
    !eLen = numBytes e

-- big-endian numbers of one length: the first byte that differs decides
below :: (ByteArrayAccess a, ByteArrayAccess b) => a -> b -> Bool
below x y = go 0
  where
    n = B.length x
    go i
        | i >= n = False
        | otherwise = case compare (B.index x i) (B.index y i) of
            EQ -> go (i + 1)
            o -> o == LT

-- | R^2 mod m for the public path, and m in bytes, kept for the last few
-- moduli, since a program verifies under the same keys again and again.
-- 'Nothing' is kept too: it means the C declines this modulus, which is
-- then not asked again.
r2For :: Integer -> IO (Maybe (Bytes, Bytes))
r2For m = do
    found <- atomicModifyIORef' r2Table $ \ks -> case break ((== m) . fst) ks of
        (before, hit : after) -> (hit : before ++ after, Just (snd hit))
        _ -> (ks, Nothing)
    case found of
        Just r2 -> return r2
        Nothing -> do
            let mLen = numBytes m
            (r2, modu) <- allocRet mLen $ \modu -> do
                _ <- Internal.i2ospOf m modu mLen
                (r, out) <- allocRet mLen $ \pout -> c_powm_r2 pout modu (fromIntegral mLen)
                return (if r == 0 then Just out else Nothing)
            let kept = fmap (\x -> (x, modu)) r2
            atomicModifyIORef' r2Table $ \ks -> (take r2TableSize ((m, kept) : ks), ())
            return kept

r2TableSize :: Int
r2TableSize = 8

r2Table :: IORef [(Integer, Maybe (Bytes, Bytes))]
r2Table = unsafePerformIO (newIORef [])
{-# NOINLINE r2Table #-}

-- safe, as the secure one is: the call is tens of microseconds at RSA
-- sizes, and the hundred nanoseconds this costs over an unsafe call is
-- nothing beside holding a capability for that long in a server
foreign import ccall safe "crypton_powm_pub_r2"
    c_powm_pub_r2
        :: Ptr Word8
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> IO CInt

foreign import ccall unsafe "crypton_powm_r2"
    c_powm_r2 :: Ptr Word8 -> Ptr Word8 -> Word32 -> IO CInt
