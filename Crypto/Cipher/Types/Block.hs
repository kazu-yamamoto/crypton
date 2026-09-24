{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module      : Crypto.Cipher.Types.Block
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Block cipher basic types
module Crypto.Cipher.Types.Block (
    -- * BlockCipher
    BlockCipher (..),
    BlockCipher128 (..),

    -- * Initialization vector (IV)
    IV (..),
    makeIV,
    nullIV,
    ivAdd,

    -- * XTS
    XTS,

    -- * AEAD
    AEAD (..),
    -- , AEADState(..)
    AEADModeImpl (..),
    aeadAppendHeader,
    aeadEncrypt,
    aeadDecrypt,
    aeadFinalize,

    -- * CFB 8 bits
) where

-- , cfb8Encrypt
-- , cfb8Decrypt

import Crypto.Cipher.Types.AEAD
import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.GF
import Crypto.Error
import Data.Word

import Crypto.Internal.ByteArray (
    ByteArray,
    ByteArrayAccess,
    Bytes,
    withByteArray,
 )
import qualified Crypto.Internal.ByteArray as B
import Data.ByteString (ByteString)
import qualified Data.ByteString as S

import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import Foreign.Storable

-- | an IV parametrized by the cipher
data IV c = forall byteArray. ByteArray byteArray => IV !byteArray

instance BlockCipher c => ByteArrayAccess (IV c) where
    withByteArray (IV z) f = withByteArray z f
    length (IV z) = B.length z
instance Eq (IV c) where
    (IV a) == (IV b) = B.eq a b

-- | XTS callback
type XTS ba cipher =
    (cipher, cipher)
    -> IV cipher
    -- ^ Usually represent the Data Unit (e.g. disk sector)
    -> DataUnitOffset
    -- ^ Offset in the data unit in number of blocks
    -> ba
    -- ^ Data
    -> ba
    -- ^ Processed Data

-- | Symmetric block cipher class
class Cipher cipher => BlockCipher cipher where
    -- | Return the size of block required for this block cipher
    blockSize :: cipher -> Int

    -- | Encrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbEncrypt :: ByteArray ba => cipher -> ba -> ba

    -- | Decrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbDecrypt :: ByteArray ba => cipher -> ba -> ba

    -- | encrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcEncrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cbcEncrypt = cbcEncryptGeneric

    -- | decrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcDecrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cbcDecrypt = cbcDecryptGeneric

    -- | encrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbEncrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cfbEncrypt = cfbEncryptGeneric

    -- | decrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbDecrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cfbDecrypt = cfbDecryptGeneric

    -- | combine using the CTR mode.
    --
    -- CTR mode produce a stream of randomized data that is combined
    -- (by XOR operation) with the input stream.
    --
    -- encryption and decryption are the same operation.
    --
    -- input can be of any size
    ctrCombine :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    ctrCombine = ctrCombineGeneric

    -- | Initialize a new AEAD State
    --
    -- When Nothing is returns, it means the mode is not handled.
    aeadInit
        :: ByteArrayAccess iv => AEADMode -> cipher -> iv -> CryptoFailable (AEAD cipher)
    aeadInit _ _ _ = CryptoFailed CryptoError_AEADModeNotSupported

-- | class of block cipher with a 128 bits block size
class BlockCipher cipher => BlockCipher128 cipher where
    -- | encrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize, and the cipher
    -- need to process 128 bits block only
    xtsEncrypt
        :: ByteArray ba
        => (cipher, cipher)
        -> IV cipher
        -- ^ Usually represent the Data Unit (e.g. disk sector)
        -> DataUnitOffset
        -- ^ Offset in the data unit in number of blocks
        -> ba
        -- ^ Plaintext
        -> ba
        -- ^ Ciphertext
    xtsEncrypt = xtsEncryptGeneric

    -- | decrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize, and the cipher
    -- need to process 128 bits block only
    xtsDecrypt
        :: ByteArray ba
        => (cipher, cipher)
        -> IV cipher
        -- ^ Usually represent the Data Unit (e.g. disk sector)
        -> DataUnitOffset
        -- ^ Offset in the data unit in number of blocks
        -> ba
        -- ^ Ciphertext
        -> ba
        -- ^ Plaintext
    xtsDecrypt = xtsDecryptGeneric

-- | Create an IV for a specified block cipher
makeIV :: (ByteArrayAccess b, BlockCipher c) => b -> Maybe (IV c)
makeIV b = toIV undefined
  where
    toIV :: BlockCipher c => c -> Maybe (IV c)
    toIV cipher
        | B.length b == sz = Just $ IV (B.convert b :: Bytes)
        | otherwise = Nothing
      where
        sz = blockSize cipher

-- | Create an IV that is effectively representing the number 0
nullIV :: BlockCipher c => IV c
nullIV = toIV undefined
  where
    toIV :: BlockCipher c => c -> IV c
    toIV cipher = IV (B.zero (blockSize cipher) :: Bytes)

-- | Increment an IV by a number.
--
-- Assume the IV is in Big Endian format.
ivAdd :: IV c -> Int -> IV c
ivAdd (IV b) i = IV $ copy b
  where
    copy :: ByteArray bs => bs -> bs
    copy bs = B.copyAndFreeze bs $ loop i (B.length bs - 1)

    loop :: Int -> Int -> Ptr Word8 -> IO ()
    loop acc ofs p
        | ofs < 0 = return ()
        | otherwise = do
            v <- peek (p `plusPtr` ofs) :: IO Word8
            let accv = acc + fromIntegral v
                (hi, lo) = accv `divMod` 256
            poke (p `plusPtr` ofs) (fromIntegral lo :: Word8)
            loop hi (ofs - 1) p

cbcEncryptGeneric
    :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cbcEncryptGeneric cipher ivini input =
    B.concat $ doEnc ivini $ slices (blockSize cipher) input
  where
    -- the blocks of the message as shared slices rather than copies: each
    -- block already costs an exclusive or and a call into the cipher, both of
    -- which allocate, and the chain makes it one block at a time
    doEnc _ [] = []
    doEnc iv (i : is) =
        let o = ecbEncrypt cipher (B.bxor iv i) `asTypeOf` input
         in o : doEnc (IV o) is

-- | How many blocks to hand the cipher at a time in the modes whose blocks do
-- not depend on one another.  Enough that the cost of a call disappears, few
-- enough that what it copies stays in cache.
blocksPerCall :: Int
blocksPerCall = 2048

-- | The input in slices of that many blocks.  A ByteString shares where
-- 'B.splitAt' copies the rest of the message, once per slice.
slices :: ByteArray ba => Int -> ba -> [ByteString]
slices bytes input = go (B.convert input)
  where
    go bs
        | S.null bs = []
        | otherwise = let (hd, tl) = S.splitAt bytes bs in hd : go tl

-- | The previous ciphertext block of every block in a slice: the incoming IV,
-- and then the slice itself one block short.
shiftedBy :: BlockCipher cipher => Int -> IV cipher -> ByteString -> ByteString
shiftedBy bsz iv c = S.append (B.convert iv) (S.take (S.length c - bsz) c)

-- | The last whole block of a slice, which is where the next one carries on
-- from.
lastBlockOf :: Int -> ByteString -> IV cipher
lastBlockOf bsz c = IV (B.convert (S.drop (S.length c - bsz) c) :: Bytes)

-- | Decryption does not chain: @P_i@ is @D(C_i)@ exclusive-ored with
-- @C_(i-1)@, so a whole slice is decrypted in one call and exclusive-ored with
-- the ciphertext moved along by a block.
cbcDecryptGeneric
    :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cbcDecryptGeneric cipher ivini input =
    B.concat $ doDec ivini $ slices (blocksPerCall * bsz) input
  where
    bsz = blockSize cipher
    conv x = B.convert x `asTypeOf` input
    xorB a b = B.bxor a b `asTypeOf` input
    doDec _ [] = []
    doDec iv (c : cs) =
        xorB (ecbDecrypt cipher (conv c)) (conv (shiftedBy bsz iv c))
            : doDec (lastBlockOf bsz c) cs

cfbEncryptGeneric
    :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cfbEncryptGeneric cipher ivini input =
    B.concat $ doEnc ivini $ slices (blockSize cipher) input
  where
    doEnc _ [] = []
    doEnc (IV iv) (i : is) =
        let o = B.bxor i (ecbEncrypt cipher iv) `asTypeOf` input
         in o : doEnc (IV o) is

-- | Nor does this one: @P_i@ is @C_i@ exclusive-ored with @E(C_(i-1))@, and
-- what gets encrypted is again the ciphertext moved along by a block.
cfbDecryptGeneric
    :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cfbDecryptGeneric cipher ivini input =
    B.concat $ doDec ivini $ slices (blocksPerCall * bsz) input
  where
    bsz = blockSize cipher
    conv x = B.convert x `asTypeOf` input
    xorB a b = B.bxor a b `asTypeOf` input
    doDec _ [] = []
    doDec iv (c : cs) =
        xorB (conv c) (ecbEncrypt cipher (conv (shiftedBy bsz iv c)))
            : doDec (lastBlockOf bsz c) cs

-- | The counters do not depend on the message at all, so a slice of them is
-- built and encrypted in one call.
ctrCombineGeneric
    :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
ctrCombineGeneric cipher ivini input =
    B.concat $ doCnt ivini $ slices (blocksPerCall * bsz) input
  where
    bsz = blockSize cipher
    conv x = B.convert x `asTypeOf` input
    xorB a b = B.bxor a b `asTypeOf` input
    doCnt _ [] = []
    doCnt iv (m : ms) =
        xorB (conv m) (ecbEncrypt cipher (counters iv n `asTypeOf` input))
            : doCnt (ivAdd iv n) ms
      where
        n = (S.length m + bsz - 1) `div` bsz

-- | The counters for a slice: the given one, then each next as the one before
-- it plus one.
--
-- One buffer, filled in place.  Asking 'ivAdd' for each of them separately
-- allocated a block per block and walked the whole width of the counter from
-- the original every time, which cost more than the cipher did: counter mode
-- ran at a quarter of what the same cipher managed in ECB, and at an eighth
-- for Blowfish.
counters :: (ByteArray ba, BlockCipher cipher) => IV cipher -> Int -> ba
counters iv n = B.allocAndFreeze (n * bsz) fill
  where
    bsz = B.length iv

    fill p = do
        B.copyByteArrayToPtr iv p
        let go k prev
                | k >= n = return ()
                | otherwise = do
                    let this = prev `plusPtr` bsz
                    copyBytes this prev bsz
                    increment this (bsz - 1)
                    go (k + 1) this
        go 1 p

    increment p ofs
        | ofs < 0 = return ()
        | otherwise = do
            v <- peek (p `plusPtr` ofs) :: IO Word8
            poke (p `plusPtr` ofs) (v + 1)
            if v == 0xff then increment p (ofs - 1) else return ()

xtsEncryptGeneric :: (ByteArray ba, BlockCipher128 cipher) => XTS ba cipher
xtsEncryptGeneric = xtsGeneric ecbEncrypt

xtsDecryptGeneric :: (ByteArray ba, BlockCipher128 cipher) => XTS ba cipher
xtsDecryptGeneric = xtsGeneric ecbDecrypt

xtsGeneric
    :: (ByteArray ba, BlockCipher128 cipher)
    => (cipher -> ba -> ba)
    -> (cipher, cipher)
    -> IV cipher
    -> DataUnitOffset
    -> ba
    -> ba
xtsGeneric f (cipher, tweakCipher) (IV iv) sPoint input =
    B.concat $ doXts iniTweak $ slices (blockSize cipher) input
  where
    encTweak = ecbEncrypt tweakCipher iv
    iniTweak = iterate xtsGFMul encTweak !! fromIntegral sPoint
    doXts _ [] = []
    doXts tweak (i : is) =
        let o = B.bxor (f cipher (B.bxor i tweak)) tweak `asTypeOf` input
         in o : doXts (xtsGFMul tweak) is

{-
-- | Encrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Encrypt :: BlockCipher a => a -> IV a -> B.byteString -> B.byteString
cfb8Encrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbEncrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` out)

-- | Decrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Decrypt :: BlockCipher a => a -> IV a -> B.byteString -> B.byteString
cfb8Decrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbDecrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` B.head m')
-}
