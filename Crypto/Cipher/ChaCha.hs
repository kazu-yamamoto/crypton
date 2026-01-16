{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.Cipher.ChaCha
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
module Crypto.Cipher.ChaCha (
    initialize,
    initializeX,
    combine,
    generate,
    State,

    -- * Simple interface for DRG purpose
    initializeSimple,
    generateSimple,
    StateSimple,

    -- * Seeking and cursor for DRG purposes
    generateSimpleBlock,
    ChaChaState (..),
) where

import Crypto.Internal.ByteArray (
    ByteArray,
    ByteArrayAccess,
    ScrubbedBytes,
 )
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat
import Crypto.Internal.Imports
import Foreign.C.Types
import Foreign.Ptr

-- | ChaCha context
newtype State = State ScrubbedBytes
    deriving (NFData)

-- | ChaCha context for DRG purpose (see Crypto.Random.ChaChaDRG)
newtype StateSimple = StateSimple ScrubbedBytes -- just ChaCha's state
    deriving (NFData)

class ChaChaState a where
    getCounter64 :: a -> Word64
    setCounter64 :: Word64 -> a -> a
    getCounter32 :: a -> Word32
    setCounter32 :: Word32 -> a -> a

instance ChaChaState State where
    getCounter64 (State st) = getCounter64' st ccrypton_chacha_get_state
    setCounter64 n (State st) = State $ setCounter64' n st ccrypton_chacha_get_state
    getCounter32 (State st) = getCounter32' st ccrypton_chacha_get_state
    setCounter32 n (State st) = State $ setCounter32' n st ccrypton_chacha_get_state

instance ChaChaState StateSimple where
    getCounter64 (StateSimple st) = getCounter64' st id
    setCounter64 n (StateSimple st) = StateSimple $ setCounter64' n st id
    getCounter32 (StateSimple st) = getCounter32' st id
    setCounter32 n (StateSimple st) = StateSimple $ setCounter32' n st id

getCounter64' :: ScrubbedBytes -> (Ptr a -> Ptr StateSimple) -> Word64
getCounter64' currSt conv =
    unsafeDoIO $ do
        B.withByteArray currSt $ \stPtr ->
            ccrypton_chacha_counter64 $ conv stPtr

getCounter32' :: ScrubbedBytes -> (Ptr a -> Ptr StateSimple) -> Word32
getCounter32' currSt conv =
    unsafeDoIO $ do
        B.withByteArray currSt $ \stPtr ->
            ccrypton_chacha_counter32 $ conv stPtr

setCounter64'
    :: Word64 -> ScrubbedBytes -> (Ptr a -> Ptr StateSimple) -> ScrubbedBytes
setCounter64' newCounter prevSt conv =
    unsafeDoIO $ do
        newSt <- B.copy prevSt (\_ -> return ())
        B.withByteArray newSt $ \stPtr ->
            ccrypton_chacha_set_counter64 (conv stPtr) newCounter
        return newSt

setCounter32'
    :: Word32 -> ScrubbedBytes -> (Ptr a -> Ptr StateSimple) -> ScrubbedBytes
setCounter32' newCounter prevSt conv =
    unsafeDoIO $ do
        newSt <- B.copy prevSt (\_ -> return ())
        B.withByteArray newSt $ \stPtr ->
            ccrypton_chacha_set_counter32 (conv stPtr) newCounter
        return newSt

-- | Initialize a new ChaCha context with the number of rounds,
-- the key and the nonce associated.
-- To use ChaCha20 defined in RFC 8439, 20, 256bits-key and 96-bits nonce must be used.
initialize
    :: (ByteArrayAccess key, ByteArrayAccess nonce)
    => Int
    -- ^ number of rounds (8,12,20)
    -> key
    -- ^ the key (128 or 256 bits)
    -> nonce
    -- ^ the nonce (64 or 96 bits)
    -> State
    -- ^ the initial ChaCha state
initialize nbRounds key nonce
    | kLen `notElem` [16, 32] =
        error "ChaCha: key length should be 128 or 256 bits"
    | nonceLen `notElem` [8, 12] =
        error "ChaCha: nonce length should be 64 or 96 bits"
    | nbRounds `notElem` [8, 12, 20] = error "ChaCha: rounds should be 8, 12 or 20"
    | otherwise = unsafeDoIO $ do
        stPtr <- B.alloc 132 $ \stPtr ->
            B.withByteArray nonce $ \noncePtr ->
                B.withByteArray key $ \keyPtr ->
                    ccrypton_chacha_init stPtr nbRounds kLen keyPtr nonceLen noncePtr
        return $ State stPtr
  where
    kLen = B.length key
    nonceLen = B.length nonce

-- | Initialize a new XChaCha context with the number of rounds,
-- the key and the nonce associated.
--
-- An XChaCha state can be used like a regular ChaCha state after initialisation.
initializeX
    :: (ByteArrayAccess key, ByteArrayAccess nonce)
    => Int
    -- ^ number of rounds (8,12,20)
    -> key
    -- ^ the key (256 bits)
    -> nonce
    -- ^ the nonce (192 bits)
    -> State
    -- ^ the initial ChaCha state
initializeX nbRounds key nonce
    | kLen /= 32 =
        error "XChaCha: key length should be 256 bits"
    | nonceLen /= 24 =
        error "XChaCha: nonce length should be 192 bits"
    | nbRounds `notElem` [8, 12, 20] =
        error "XChaCha: rounds should be 8, 12 or 20"
    | otherwise = unsafeDoIO $ do
        stPtr <- B.alloc 132 $ \stPtr ->
            B.withByteArray nonce $ \noncePtr ->
                B.withByteArray key $ \keyPtr ->
                    ccrypton_xchacha_init stPtr nbRounds keyPtr noncePtr
        return $ State stPtr
  where
    kLen = B.length key
    nonceLen = B.length nonce

-- | Initialize simple ChaCha State
--
-- The seed need to be at least 40 bytes long
initializeSimple
    :: ByteArrayAccess seed
    => seed
    -- ^ a 40 bytes long seed
    -> StateSimple
initializeSimple seed
    | sLen < 40 = error "ChaCha Random: seed length should be 40 bytes"
    | otherwise = unsafeDoIO $ do
        stPtr <- B.alloc 64 $ \stPtr ->
            B.withByteArray seed $ \seedPtr ->
                ccrypton_chacha_init_core stPtr 32 seedPtr 8 (seedPtr `plusPtr` 32)
        return $ StateSimple stPtr
  where
    sLen = B.length seed

-- | Combine the chacha output and an arbitrary message with a xor,
-- and return the combined output and the new state.
combine
    :: ByteArray ba
    => State
    -- ^ the current ChaCha state
    -> ba
    -- ^ the source to xor with the generator
    -> (ba, State)
combine prevSt@(State prevStMem) src
    | B.null src = (B.empty, prevSt)
    | otherwise = unsafeDoIO $ do
        (out, st) <- B.copyRet prevStMem $ \ctx ->
            B.alloc (B.length src) $ \dstPtr ->
                B.withByteArray src $ \srcPtr ->
                    ccrypton_chacha_combine dstPtr ctx srcPtr (fromIntegral $ B.length src)
        return (out, State st)

-- | Generate a number of bytes from the ChaCha output directly
generate
    :: ByteArray ba
    => State
    -- ^ the current ChaCha state
    -> Int
    -- ^ the length of data to generate
    -> (ba, State)
generate prevSt@(State prevStMem) len
    | len <= 0 = (B.empty, prevSt)
    | otherwise = unsafeDoIO $ do
        (out, st) <- B.copyRet prevStMem $ \ctx ->
            B.alloc len $ \dstPtr ->
                ccrypton_chacha_generate dstPtr ctx (fromIntegral len)
        return (out, State st)

-- | similar to 'generate' but assume certains values
generateSimple
    :: ByteArray ba
    => StateSimple
    -> Int
    -> (ba, StateSimple)
generateSimple (StateSimple prevSt) nbBytes = unsafeDoIO $ do
    newSt <- B.copy prevSt (\_ -> return ())
    output <- B.alloc nbBytes $ \dstPtr ->
        B.withByteArray newSt $ \stPtr ->
            ccrypton_chacha_random 8 dstPtr stPtr (fromIntegral nbBytes)
    return (output, StateSimple newSt)

-- | similar to 'generate' but accepts a number of rounds, and always generates
--   64 bytes (a single block)
generateSimpleBlock
    :: ByteArray ba
    => Word8
    -> StateSimple
    -> (ba, StateSimple)
generateSimpleBlock nbRounds (StateSimple prevSt)
    | nbRounds `notElem` [8, 12, 20] = error "ChaCha: rounds should be 8, 12 or 20"
    | otherwise = unsafeDoIO $ do
        newSt <- B.copy prevSt (\_ -> return ())
        output <- B.alloc 64 $ \dstPtr ->
            B.withByteArray newSt $ \stPtr ->
                ccrypton_chacha_generate_simple_block dstPtr stPtr nbRounds
        return (output, StateSimple newSt)

foreign import ccall unsafe "crypton_chacha_init_core"
    ccrypton_chacha_init_core
        :: Ptr StateSimple -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO ()

foreign import ccall unsafe "crypton_chacha_init"
    ccrypton_chacha_init
        :: Ptr State -> Int -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO ()

foreign import ccall unsafe "crypton_xchacha_init"
    ccrypton_xchacha_init :: Ptr State -> Int -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall "crypton_chacha_combine"
    ccrypton_chacha_combine :: Ptr Word8 -> Ptr State -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "crypton_chacha_generate"
    ccrypton_chacha_generate :: Ptr Word8 -> Ptr State -> CUInt -> IO ()

foreign import ccall "crypton_chacha_random"
    ccrypton_chacha_random :: Int -> Ptr Word8 -> Ptr StateSimple -> CUInt -> IO ()

foreign import ccall unsafe "crypton_chacha_counter64"
    ccrypton_chacha_counter64 :: Ptr StateSimple -> IO Word64

foreign import ccall unsafe "crypton_chacha_set_counter64"
    ccrypton_chacha_set_counter64 :: Ptr StateSimple -> Word64 -> IO ()

foreign import ccall unsafe "crypton_chacha_counter32"
    ccrypton_chacha_counter32 :: Ptr StateSimple -> IO Word32

foreign import ccall unsafe "crypton_chacha_set_counter32"
    ccrypton_chacha_set_counter32 :: Ptr StateSimple -> Word32 -> IO ()

foreign import ccall unsafe "crypton_chacha_generate_simple_block"
    ccrypton_chacha_generate_simple_block
        :: Ptr Word8 -> Ptr StateSimple -> Word8 -> IO ()

foreign import capi unsafe "crypton_chacha.h crypton_chacha_get_state"
    ccrypton_chacha_get_state :: Ptr State -> Ptr StateSimple
