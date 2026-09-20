{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Cipher.DES.Primitive
-- License     : BSD-style
-- Stability   : experimental
-- Portability : Good
--
-- The DES block operation, as FIPS 46-3 defines it, over the C in
-- @cbits/crypton_des.c@.
--
-- A 'Schedule' holds the round keys of one or more stages in the order they
-- are applied, which is what lets single DES and the three stage constructions
-- share one entry point.
module Crypto.Cipher.DES.Primitive (
    Schedule,
    Direction (..),
    schedule,
    ecb,
) where

import Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat (unsafeDoIO)
import Data.Word
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr, plusPtr)

-- | Which way a stage runs.
data Direction = Encrypt | Decrypt
    deriving (Show, Eq)

-- | The round keys of one or more stages, in the order they are applied.
newtype Schedule = Schedule Bytes
    deriving (Eq)

-- | Bytes per stage: sixteen rounds of eight six-bit values.
stageSize :: Int
stageSize = 16 * 8

-- | The block size DES works in.
blockBytes :: Int
blockBytes = 8

-- | Build the schedule for a sequence of stages, each an eight byte key and
-- the direction that stage runs in.  Shorter keys are rejected by the callers,
-- which know their own size; the bytes past the eighth are not read.
schedule :: ByteArrayAccess key => [(Direction, key)] -> Schedule
schedule stages =
    Schedule $ B.allocAndFreeze (stageSize * length stages) $ \dst ->
        mapM_ (uncurry (one dst)) (zip [0 ..] stages)
  where
    one dst i (dir, key) =
        B.withByteArray key $ \k ->
            c_des_init (dst `plusPtr` (i * stageSize)) k (reverseFlag dir)
    reverseFlag Encrypt = 0
    reverseFlag Decrypt = 1

-- | Apply every stage of the schedule, in order, to each block of the input.
ecb :: ByteArray ba => Schedule -> ba -> ba
ecb (Schedule sched) input
    | len `mod` blockBytes /= 0 =
        error $
            "Crypto.Cipher.DES: input length must be a multiple of block size (8). Its length is: "
                ++ show len
    | otherwise = unsafeDoIO $
        B.alloc len $ \out ->
            B.withByteArray sched $ \ks ->
                B.withByteArray input $ \inp ->
                    c_des_ecb
                        out
                        ks
                        (fromIntegral (B.length sched `div` stageSize))
                        inp
                        (fromIntegral (len `div` blockBytes))
  where
    len = B.length input

foreign import ccall unsafe "crypton_des.h crypton_des_init"
    c_des_init :: Ptr Word8 -> Ptr Word8 -> CInt -> IO ()

foreign import ccall unsafe "crypton_des.h crypton_des_ecb"
    c_des_ecb :: Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO ()
