{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module      : Crypto.Cipher.AES.Primitive
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
module Crypto.Cipher.AES.Primitive (
    -- * Block cipher data types
    AES,

    -- * Authenticated encryption block cipher types
    AESGCM,
    AESOCB,

    -- * Creation
    initAES,

    -- * Miscellanea

    -- * Encryption
    encryptECB,
    encryptCBC,
    encryptCTR,
    encryptXTS,

    -- * Decryption
    decryptECB,
    decryptCBC,
    decryptCTR,
    decryptXTS,

    -- * CTR with 32-bit wrapping
    combineC32,

    -- * Incremental GCM
    gcmMode,
    gcmInit,
    AESGCMKey,
    gcmKeyInit,
    gcmFullEncrypt,
    gcmFullEncryptMask,
    gcmFullDecrypt,
    gcmFullDecryptTag,
    gcmAeadInit,

    -- * Incremental OCB
    ocbMode,
    ocbModeWithTagLength,
    ocbInit,
    ocbInitWithTagLength,

    -- * CCM
    ccmMode,
    ccmInit,
) where

import Data.Word
import Foreign.C.String
import Foreign.C.Types
import Foreign.Ptr

import Crypto.Cipher.Types
import Crypto.Cipher.Types.Block (IV (..))
import Crypto.Error
import Crypto.Internal.ByteArray (
    ByteArray,
    ByteArrayAccess,
    ScrubbedBytes,
    withByteArray,
 )
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat
import Crypto.Internal.Imports

instance Cipher AES where
    cipherName _ = "AES"
    cipherKeySize _ = KeySizeEnum [16, 24, 32]
    cipherInit k = initAES k

instance BlockCipher AES where
    blockSize _ = 16
    ecbEncrypt = encryptECB
    ecbDecrypt = decryptECB
    cbcEncrypt = encryptCBC
    cbcDecrypt = decryptCBC
    ctrCombine = encryptCTR
    aeadInit AEAD_GCM aes iv = gcmAeadInit aes iv
    aeadInit AEAD_OCB aes iv = CryptoPassed $ AEAD (ocbMode aes) (ocbInit aes iv)
    aeadInit (AEAD_CCM n m l) aes iv = AEAD (ccmMode aes) <$> ccmInit aes iv n m l
    aeadInit _ _ _ = CryptoFailed CryptoError_AEADModeNotSupported
instance BlockCipher128 AES where
    xtsEncrypt = encryptXTS
    xtsDecrypt = decryptXTS

-- | Create an AES AEAD context for GCM, refusing the zero-length IV that
-- SP 800-38D 5.2.1.1 forbids: any length other than 96 bits is fed to
-- GHASH, and for the empty IV that makes J0 the GHASH of the empty
-- string, which leaks the authentication key.
gcmAeadInit :: ByteArrayAccess iv => AES -> iv -> CryptoFailable (AEAD c)
gcmAeadInit aes iv
    | B.length iv == 0 = CryptoFailed CryptoError_IvSizeInvalid
    | otherwise = CryptoPassed $ AEAD (gcmMode aes) (gcmInit aes iv)

-- | Create an AES AEAD implementation for GCM
gcmMode :: AES -> AEADModeImpl AESGCM
gcmMode aes =
    AEADModeImpl
        { aeadImplAppendHeader = gcmAppendAAD
        , aeadImplEncrypt = gcmAppendEncrypt aes
        , aeadImplDecrypt = gcmAppendDecrypt aes
        , aeadImplFinalize = gcmFinish aes
        }

-- | Create an AES AEAD implementation for OCB
ocbMode :: AES -> AEADModeImpl AESOCB
ocbMode aes =
    AEADModeImpl
        { aeadImplAppendHeader = ocbAppendAAD aes
        , aeadImplEncrypt = ocbAppendEncrypt aes
        , aeadImplDecrypt = ocbAppendDecrypt aes
        , aeadImplFinalize = ocbFinish aes
        }

ocbModeWithTagLength :: AES -> Int -> AEADModeImpl AESOCB
ocbModeWithTagLength aes taglen =
    AEADModeImpl
        { aeadImplAppendHeader = ocbAppendAAD aes
        , aeadImplEncrypt = ocbAppendEncrypt aes
        , aeadImplDecrypt = ocbAppendDecrypt aes
        , aeadImplFinalize = \ocb _ -> ocbFinish aes ocb taglen
        }

-- | Create an AES AEAD implementation for CCM
ccmMode :: AES -> AEADModeImpl AESCCM
ccmMode aes =
    AEADModeImpl
        { aeadImplAppendHeader = ccmAppendAAD aes
        , aeadImplEncrypt = ccmEncrypt aes
        , aeadImplDecrypt = ccmDecrypt aes
        , aeadImplFinalize = ccmFinish aes
        }

-- | AES Context (pre-processed key)
newtype AES = AES ScrubbedBytes
    deriving (NFData)

-- | AESGCM State
newtype AESGCM = AESGCM ScrubbedBytes
    deriving (NFData)

-- | AESOCB State
newtype AESOCB = AESOCB ScrubbedBytes
    deriving (NFData)

-- | AESCCM State
newtype AESCCM = AESCCM ScrubbedBytes
    deriving (NFData)

sizeGCM :: Int
sizeGCM = 320

-- | The size of what a key determines, which is the 320 bytes above and the
-- powers of H the fused path reads: sixteen of them, and sixteen more for
-- the term the Karatsuba multiplication would otherwise work out every time.
-- The same on every platform, so that this is one number rather than one per
-- architecture; the powers are filled only where that path is compiled in.
sizeGCMKey :: Int
sizeGCMKey = 832

sizeOCB :: Int
sizeOCB = 160

sizeCCM :: Int
sizeCCM = 80

keyToPtr :: AES -> (Ptr AES -> IO a) -> IO a
keyToPtr (AES b) f = withByteArray b (f . castPtr)

ivToPtr :: ByteArrayAccess iv => iv -> (Ptr Word8 -> IO a) -> IO a
ivToPtr iv f = withByteArray iv (f . castPtr)

withKeyAndIV
    :: ByteArrayAccess iv => AES -> iv -> (Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKeyAndIV ctx iv f = keyToPtr ctx $ \kptr -> ivToPtr iv $ \ivp -> f kptr ivp

withKey2AndIV
    :: ByteArrayAccess iv
    => AES -> AES -> iv -> (Ptr AES -> Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKey2AndIV key1 key2 iv f =
    keyToPtr key1 $ \kptr1 -> keyToPtr key2 $ \kptr2 -> ivToPtr iv $ \ivp -> f kptr1 kptr2 ivp

withGCMKeyAndCopySt
    :: AES -> AESGCM -> (Ptr AESGCM -> Ptr AES -> IO a) -> IO (a, AESGCM)
withGCMKeyAndCopySt aes (AESGCM gcmSt) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- B.copy gcmSt (\_ -> return ())
        a <- withByteArray newSt $ \gcmStPtr -> f (castPtr gcmStPtr) aesPtr
        return (a, AESGCM newSt)

withNewGCMSt :: AESGCM -> (Ptr AESGCM -> IO ()) -> IO AESGCM
withNewGCMSt (AESGCM gcmSt) f = B.copy gcmSt (f . castPtr) >>= \sm2 -> return (AESGCM sm2)

withOCBKeyAndCopySt
    :: AES -> AESOCB -> (Ptr AESOCB -> Ptr AES -> IO a) -> IO (a, AESOCB)
withOCBKeyAndCopySt aes (AESOCB gcmSt) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- B.copy gcmSt (\_ -> return ())
        a <- withByteArray newSt $ \gcmStPtr -> f (castPtr gcmStPtr) aesPtr
        return (a, AESOCB newSt)

withCCMKeyAndCopySt
    :: AES -> AESCCM -> (Ptr AESCCM -> Ptr AES -> IO a) -> IO (a, AESCCM)
withCCMKeyAndCopySt aes (AESCCM ccmSt) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- B.copy ccmSt (\_ -> return ())
        a <- withByteArray newSt $ \ccmStPtr -> f (castPtr ccmStPtr) aesPtr
        return (a, AESCCM newSt)

-- | Initialize a new context with a key
--
-- Key needs to be of length 16, 24 or 32 bytes. Any other values will return failure
initAES :: ByteArrayAccess key => key -> CryptoFailable AES
initAES k
    | len == 16 = CryptoPassed $ initWithRounds 10
    | len == 24 = CryptoPassed $ initWithRounds 12
    | len == 32 = CryptoPassed $ initWithRounds 14
    | otherwise = CryptoFailed CryptoError_KeySizeInvalid
  where
    len = B.length k
    initWithRounds nbR = AES $ B.allocAndFreeze (16 + 2 * 2 * 16 * nbR) aesInit
    aesInit ptr = withByteArray k $ \ikey ->
        c_aes_init (castPtr ptr) (castPtr ikey) (fromIntegral len)

-- | encrypt using Electronic Code Book (ECB)
{-# NOINLINE encryptECB #-}
encryptECB :: ByteArray ba => AES -> ba -> ba
encryptECB = doECB c_aes_encrypt_ecb

-- | encrypt using Cipher Block Chaining (CBC)
{-# NOINLINE encryptCBC #-}
encryptCBC
    :: ByteArray ba
    => AES
    -- ^ AES Context
    -> IV AES
    -- ^ Initial vector of AES block size
    -> ba
    -- ^ plaintext
    -> ba
    -- ^ ciphertext
encryptCBC = doCBC c_aes_encrypt_cbc

-- | encrypt using Counter mode (CTR)
--
-- in CTR mode encryption and decryption is the same operation.
{-# NOINLINE encryptCTR #-}
encryptCTR
    :: ByteArray ba
    => AES
    -- ^ AES Context
    -> IV AES
    -- ^ initial vector of AES block size (usually representing a 128 bit integer)
    -> ba
    -- ^ plaintext input
    -> ba
    -- ^ ciphertext output
encryptCTR ctx iv input
    | len <= 0 = B.empty
    | B.length iv /= 16 =
        error $
            "AES error: IV length must be block size (16). Its length is: "
                ++ (show $ B.length iv)
    | otherwise = B.allocAndFreeze len doEncrypt
  where
    doEncrypt o = withKeyAndIV ctx iv $ \k v -> withByteArray input $ \i ->
        c_aes_encrypt_ctr (castPtr o) k v i (fromIntegral len)
    len = B.length input

-- | encrypt using XTS
--
-- the first key is the normal block encryption key
-- the second key is used for the initial block tweak
{-# NOINLINE encryptXTS #-}
encryptXTS
    :: ByteArray ba
    => (AES, AES)
    -- ^ AES cipher and tweak context
    -> IV AES
    -- ^ a 128 bits IV, typically a sector or a block offset in XTS
    -> Word32
    -- ^ number of rounds to skip, also seen a 16 byte offset in the sector or block.
    -> ba
    -- ^ input to encrypt
    -> ba
    -- ^ output encrypted
encryptXTS = doXTS c_aes_encrypt_xts

-- | decrypt using Electronic Code Book (ECB)
{-# NOINLINE decryptECB #-}
decryptECB :: ByteArray ba => AES -> ba -> ba
decryptECB = doECB c_aes_decrypt_ecb

-- | decrypt using Cipher block chaining (CBC)
{-# NOINLINE decryptCBC #-}
decryptCBC :: ByteArray ba => AES -> IV AES -> ba -> ba
decryptCBC = doCBC c_aes_decrypt_cbc

-- | decrypt using Counter mode (CTR).
--
-- in CTR mode encryption and decryption is the same operation.
decryptCTR
    :: ByteArray ba
    => AES
    -- ^ AES Context
    -> IV AES
    -- ^ initial vector, usually representing a 128 bit integer
    -> ba
    -- ^ ciphertext input
    -> ba
    -- ^ plaintext output
decryptCTR = encryptCTR

-- | decrypt using XTS
{-# NOINLINE decryptXTS #-}
decryptXTS
    :: ByteArray ba
    => (AES, AES)
    -- ^ AES cipher and tweak context
    -> IV AES
    -- ^ a 128 bits IV, typically a sector or a block offset in XTS
    -> Word32
    -- ^ number of rounds to skip, also seen a 16 byte offset in the sector or block.
    -> ba
    -- ^ input to decrypt
    -> ba
    -- ^ output decrypted
decryptXTS = doXTS c_aes_decrypt_xts

-- | encrypt/decrypt using Counter mode (32-bit wrapping used in AES-GCM-SIV)
{-# NOINLINE combineC32 #-}
combineC32
    :: ByteArray ba
    => AES
    -- ^ AES Context
    -> IV AES
    -- ^ initial vector of AES block size (usually representing a 128 bit integer)
    -> ba
    -- ^ plaintext input
    -> ba
    -- ^ ciphertext output
combineC32 ctx iv input
    | len <= 0 = B.empty
    | B.length iv /= 16 =
        error $
            "AES error: IV length must be block size (16). Its length is: "
                ++ show (B.length iv)
    | otherwise = B.allocAndFreeze len doEncrypt
  where
    doEncrypt o = withKeyAndIV ctx iv $ \k v -> withByteArray input $ \i ->
        c_aes_encrypt_c32 (castPtr o) k v i (fromIntegral len)
    len = B.length input

{-# INLINE doECB #-}
doECB
    :: ByteArray ba
    => (Ptr b -> Ptr AES -> CString -> CUInt -> IO ())
    -> AES
    -> ba
    -> ba
doECB f ctx input
    | len == 0 = B.empty
    | r /= 0 =
        error $
            "Encryption error: input length must be a multiple of block size (16). Its length is: "
                ++ (show len)
    | otherwise =
        B.allocAndFreeze len $ \o ->
            keyToPtr ctx $ \k ->
                withByteArray input $ \i ->
                    f (castPtr o) k i (fromIntegral nbBlocks)
  where
    (nbBlocks, r) = len `quotRem` 16
    len = B.length input

{-# INLINE doCBC #-}
doCBC
    :: ByteArray ba
    => (Ptr b -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ())
    -> AES
    -> IV AES
    -> ba
    -> ba
doCBC f ctx (IV iv) input
    | len == 0 = B.empty
    | r /= 0 =
        error $
            "Encryption error: input length must be a multiple of block size (16). Its length is: "
                ++ (show len)
    | otherwise = B.allocAndFreeze len $ \o ->
        withKeyAndIV ctx iv $ \k v ->
            withByteArray input $ \i ->
                f (castPtr o) k v i (fromIntegral nbBlocks)
  where
    (nbBlocks, r) = len `quotRem` 16
    len = B.length input

{-# INLINE doXTS #-}
doXTS
    :: ByteArray ba
    => (Ptr b -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ())
    -> (AES, AES)
    -> IV AES
    -> Word32
    -> ba
    -> ba
doXTS f (key1, key2) iv spoint input
    | len == 0 = B.empty
    | r /= 0 =
        error $
            "Encryption error: input length must be a multiple of block size (16) for now. Its length is: "
                ++ (show len)
    | otherwise = B.allocAndFreeze len $ \o -> withKey2AndIV key1 key2 iv $ \k1 k2 v -> withByteArray input $ \i ->
        f (castPtr o) k1 k2 v (fromIntegral spoint) i (fromIntegral nbBlocks)
  where
    (nbBlocks, r) = len `quotRem` 16
    len = B.length input

------------------------------------------------------------------------
-- GCM
------------------------------------------------------------------------

-- | initialize a gcm context
{-# NOINLINE gcmInit #-}
gcmInit :: ByteArrayAccess iv => AES -> iv -> AESGCM
gcmInit ctx iv = unsafeDoIO $ do
    sm <- B.alloc sizeGCM $ \gcmStPtr ->
        withKeyAndIV ctx iv $ \k v ->
            c_aes_gcm_init (castPtr gcmStPtr) k v (fromIntegral $ B.length iv)
    return $ AESGCM sm

-- | How long a message may be and still be handed to an unsafe foreign call.
-- Four kibibytes is about half a microsecond of work, and it takes in a
-- datagram of any size a network will carry.
shortMessage :: Int
shortMessage = 4096

-- | The part of a GCM state the key alone determines: H, which is the key
-- applied to a block of zeroes, and the table of its multiples.  That is 256
-- of the 320 bytes of a GCM state, and it is the same for every message sent
-- under one key, so a caller that keeps a key can build this once rather than
-- once for every message.
newtype AESGCMKey = AESGCMKey ScrubbedBytes

-- | Build the key part of a GCM state.
{-# NOINLINE gcmKeyInit #-}
gcmKeyInit :: AES -> AESGCMKey
gcmKeyInit ctx = AESGCMKey $ B.allocAndFreeze sizeGCMKey $ \p ->
    keyToPtr ctx $ \k -> c_aes_gcm_key_init (castPtr p) k

-- | Authenticate and encrypt one message in a single call: the nonce, the
-- additional data, the plaintext and the tag, with no state crossing back
-- into Haskell in between.  The result is the ciphertext followed by the tag.
{-# INLINABLE gcmFullEncrypt #-}
gcmFullEncrypt
    :: (ByteArrayAccess iv, ByteArrayAccess aad, ByteArrayAccess ba, ByteArray output)
    => AES -> AESGCMKey -> iv -> aad -> ba -> Int -> output
gcmFullEncrypt ctx (AESGCMKey gk) iv aad input taglen =
    B.allocAndFreeze (B.length input + taglen) $ \out ->
        B.withByteArray gk $ \gkp ->
            keyToPtr ctx $ \k ->
                B.withByteArray iv $ \ivp ->
                    B.withByteArray aad $ \aadp ->
                        B.withByteArray input $ \inp ->
                            call
                                out
                                (castPtr gkp)
                                k
                                ivp
                                (fromIntegral $ B.length iv)
                                aadp
                                (fromIntegral $ B.length aad)
                                inp
                                (fromIntegral $ B.length input)
                                (fromIntegral taglen)
  where
    -- An unsafe call keeps a capability for as long as it runs, so it is only
    -- right for work that is over quickly.  A message this side of
    -- 'shortMessage' is, and it is the short ones the saving matters for: a
    -- safe call costs about 0.075 us whatever the length, which is a fifth of
    -- a 1440-byte packet and a percent of a 16 KiB record.
    call
        | B.length input <= shortMessage = c_aes_gcm_full_encrypt_unsafe
        | otherwise = c_aes_gcm_full_encrypt

-- | Encrypt, and from a sample of the ciphertext just produced make the
-- header protection mask, into buffers the caller owns.  QUIC takes its
-- sample from the ciphertext, so the mask cannot be had before the
-- encryption; it can be had before coming back, and with the buffers already
-- there nothing is allocated for either.
--
-- @sampleoff@ is where the sixteen bytes of sample begin in the output.
{-# INLINABLE gcmFullEncryptMask #-}
gcmFullEncryptMask
    :: (ByteArrayAccess iv, ByteArrayAccess aad, ByteArrayAccess ba)
    => AES
    -> AESGCMKey
    -> AES
    -> iv
    -> aad
    -> ba
    -> Int
    -> Int
    -> Ptr Word8
    -> Ptr Word8
    -> IO ()
gcmFullEncryptMask ctx (AESGCMKey gk) hpctx iv aad input taglen sampleoff outp maskp =
    B.withByteArray gk $ \gkp ->
        keyToPtr ctx $ \k ->
            keyToPtr hpctx $ \hk ->
                B.withByteArray iv $ \ivp ->
                    B.withByteArray aad $ \aadp ->
                        B.withByteArray input $ \inp ->
                            call
                                outp
                                (castPtr gkp)
                                k
                                ivp
                                (fromIntegral $ B.length iv)
                                aadp
                                (fromIntegral $ B.length aad)
                                inp
                                (fromIntegral $ B.length input)
                                (fromIntegral taglen)
                                hk
                                (fromIntegral sampleoff)
                                maskp
  where
    call
        | B.length input <= shortMessage = c_aes_gcm_full_encrypt_mask_unsafe
        | otherwise = c_aes_gcm_full_encrypt_mask

-- | The same the other way, with the tag compared here rather than by the
-- caller: 'Nothing' when it does not match, and every byte of it is looked at
-- either way.  The ciphertext comes in without its tag, which is given
-- separately.
{-# INLINABLE gcmFullDecrypt #-}
gcmFullDecrypt
    :: ( ByteArrayAccess iv
       , ByteArrayAccess aad
       , ByteArrayAccess ba
       , ByteArrayAccess tag
       , ByteArray output
       )
    => AES -> AESGCMKey -> iv -> aad -> ba -> tag -> Maybe output
gcmFullDecrypt ctx (AESGCMKey gk) iv aad input tag = unsafeDoIO $ do
    (r, out) <- B.allocRet (B.length input) $ \outp ->
        B.withByteArray gk $ \gkp ->
            keyToPtr ctx $ \k ->
                B.withByteArray iv $ \ivp ->
                    B.withByteArray aad $ \aadp ->
                        B.withByteArray input $ \inp ->
                            B.withByteArray tag $ \tagp ->
                                call
                                    outp
                                    (castPtr gkp)
                                    k
                                    ivp
                                    (fromIntegral $ B.length iv)
                                    aadp
                                    (fromIntegral $ B.length aad)
                                    inp
                                    (fromIntegral $ B.length input)
                                    tagp
                                    (fromIntegral $ B.length tag)
    return $ if r /= 0 then Just out else Nothing
  where
    call
        | B.length input <= shortMessage = c_aes_gcm_full_decrypt_unsafe
        | otherwise = c_aes_gcm_full_decrypt

-- | Decrypt one message and hand back the tag that was computed over it,
-- rather than comparing it here.
--
-- For a caller that holds the expected tag in a form of its own and will
-- compare it itself.  Compare the two 'AuthTag's with '==', whose instance
-- for that type is a constant-time comparison; taking them apart and
-- comparing the bytes is how this goes wrong.
--
-- Where the tag simply arrives after the ciphertext, 'gcmFullDecrypt' is the
-- one to use: it compares in C and never puts a tag in the caller's hands.
{-# INLINABLE gcmFullDecryptTag #-}
gcmFullDecryptTag
    :: ( ByteArrayAccess iv
       , ByteArrayAccess aad
       , ByteArrayAccess ba
       , ByteArray output
       )
    => AES -> AESGCMKey -> iv -> aad -> ba -> Int -> (output, AuthTag)
gcmFullDecryptTag ctx (AESGCMKey gk) iv aad input taglen = unsafeDoIO $ do
    (tagbs, out) <- B.allocRet (B.length input) $ \outp ->
        B.alloc taglen $ \tagp ->
            B.withByteArray gk $ \gkp ->
                keyToPtr ctx $ \k ->
                    B.withByteArray iv $ \ivp ->
                        B.withByteArray aad $ \aadp ->
                            B.withByteArray input $ \inp ->
                                call
                                    outp
                                    tagp
                                    (castPtr gkp)
                                    k
                                    ivp
                                    (fromIntegral $ B.length iv)
                                    aadp
                                    (fromIntegral $ B.length aad)
                                    inp
                                    (fromIntegral $ B.length input)
                                    (fromIntegral taglen)
    return (out, AuthTag $ B.convert (tagbs :: B.Bytes))
  where
    call
        | B.length input <= shortMessage = c_aes_gcm_full_decrypt_tag_unsafe
        | otherwise = c_aes_gcm_full_decrypt_tag

-- | append data which is only going to be authenticated to the GCM context.
--
-- needs to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE gcmAppendAAD #-}
gcmAppendAAD :: ByteArrayAccess aad => AESGCM -> aad -> AESGCM
gcmAppendAAD gcmSt input = unsafeDoIO doAppend
  where
    doAppend =
        withNewGCMSt gcmSt $ \gcmStPtr ->
            withByteArray input $ \i ->
                c_aes_gcm_aad gcmStPtr i (fromIntegral $ B.length input)

-- | append data to encrypt and append to the GCM context
--
-- the bytearray needs to be a multiple of AES block size, unless it's the last call to this function.
-- needs to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendEncrypt #-}
gcmAppendEncrypt :: ByteArray ba => AES -> AESGCM -> ba -> (ba, AESGCM)
gcmAppendEncrypt ctx gcm input = unsafeDoIO $ withGCMKeyAndCopySt ctx gcm doEnc
  where
    len = B.length input
    doEnc gcmStPtr aesPtr =
        B.alloc len $ \o ->
            withByteArray input $ \i ->
                c_aes_gcm_encrypt (castPtr o) gcmStPtr aesPtr i (fromIntegral len)

-- | append data to decrypt and append to the GCM context
--
-- the bytearray needs to be a multiple of AES block size, unless it's the last call to this function.
-- needs to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendDecrypt #-}
gcmAppendDecrypt :: ByteArray ba => AES -> AESGCM -> ba -> (ba, AESGCM)
gcmAppendDecrypt ctx gcm input = unsafeDoIO $ withGCMKeyAndCopySt ctx gcm doDec
  where
    len = B.length input
    doDec gcmStPtr aesPtr =
        B.alloc len $ \o ->
            withByteArray input $ \i ->
                c_aes_gcm_decrypt (castPtr o) gcmStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from GCM context
{-# NOINLINE gcmFinish #-}
gcmFinish :: AES -> AESGCM -> Int -> AuthTag
gcmFinish ctx gcm taglen = AuthTag $ B.take taglen computeTag
  where
    computeTag = B.allocAndFreeze 16 $ \t ->
        withGCMKeyAndCopySt ctx gcm (c_aes_gcm_finish (castPtr t)) >> return ()

------------------------------------------------------------------------
-- OCB v3
------------------------------------------------------------------------

-- | initialize an ocb context
{-# NOINLINE ocbInit #-}
ocbInit :: ByteArrayAccess iv => AES -> iv -> AESOCB
ocbInit ctx iv = unsafeDoIO $ do
    sm <- B.alloc sizeOCB $ \ocbStPtr ->
        withKeyAndIV ctx iv $ \k v ->
            c_aes_ocb_init
                (castPtr ocbStPtr)
                k
                v
                (fromIntegral $ B.length iv)
                16
    return $ AESOCB sm

-- | initialize an OCB context with a fixed authentication tag length.
--
-- The tag length is expressed in bytes and must be in [0..16].
-- The IV length must be in [1..15] bytes per RFC 7253.
{-# NOINLINE ocbInitWithTagLength #-}
ocbInitWithTagLength
    :: ByteArrayAccess iv => AES -> iv -> Int -> CryptoFailable AESOCB
ocbInitWithTagLength ctx iv taglen
    | taglen < 0 || taglen > 16 =
        CryptoFailed CryptoError_AuthenticationTagSizeInvalid
    | ivlen < 1 || ivlen > 15 = CryptoFailed CryptoError_IvSizeInvalid
    | otherwise = CryptoPassed $ unsafeDoIO $ do
        sm <- B.alloc sizeOCB $ \ocbStPtr ->
            withKeyAndIV ctx iv $ \k v ->
                c_aes_ocb_init
                    (castPtr ocbStPtr)
                    k
                    v
                    (fromIntegral ivlen)
                    (fromIntegral taglen)
        return $ AESOCB sm
  where
    ivlen = B.length iv

-- | append data which is going to just be authenticated to the OCB context.
--
-- need to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE ocbAppendAAD #-}
ocbAppendAAD :: ByteArrayAccess aad => AES -> AESOCB -> aad -> AESOCB
ocbAppendAAD ctx ocb input = unsafeDoIO (snd `fmap` withOCBKeyAndCopySt ctx ocb doAppend)
  where
    doAppend ocbStPtr aesPtr =
        withByteArray input $ \i ->
            c_aes_ocb_aad ocbStPtr aesPtr i (fromIntegral $ B.length input)

-- | append data to encrypt and append to the OCB context
--
-- the bytearray needs to be a multiple of the AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ocbAppendEncrypt #-}
ocbAppendEncrypt :: ByteArray ba => AES -> AESOCB -> ba -> (ba, AESOCB)
ocbAppendEncrypt ctx ocb input = unsafeDoIO $ withOCBKeyAndCopySt ctx ocb doEnc
  where
    len = B.length input
    doEnc ocbStPtr aesPtr =
        B.alloc len $ \o ->
            withByteArray input $ \i ->
                c_aes_ocb_encrypt (castPtr o) ocbStPtr aesPtr i (fromIntegral len)

-- | append data to decrypt and append to the OCB context
--
-- the bytearray needs to be a multiple of the AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ocbAppendDecrypt #-}
ocbAppendDecrypt :: ByteArray ba => AES -> AESOCB -> ba -> (ba, AESOCB)
ocbAppendDecrypt ctx ocb input = unsafeDoIO $ withOCBKeyAndCopySt ctx ocb doDec
  where
    len = B.length input
    doDec ocbStPtr aesPtr =
        B.alloc len $ \o ->
            withByteArray input $ \i ->
                c_aes_ocb_decrypt (castPtr o) ocbStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from OCB context
{-# NOINLINE ocbFinish #-}
ocbFinish :: AES -> AESOCB -> Int -> AuthTag
ocbFinish ctx ocb taglen = AuthTag $ B.take taglen computeTag
  where
    computeTag = B.allocAndFreeze 16 $ \t ->
        withOCBKeyAndCopySt ctx ocb (c_aes_ocb_finish (castPtr t)) >> return ()

ccmGetM :: CCM_M -> Int
ccmGetL :: CCM_L -> Int
ccmGetM m = case m of
    CCM_M4 -> 4
    CCM_M6 -> 6
    CCM_M8 -> 8
    CCM_M10 -> 10
    CCM_M12 -> 12
    CCM_M14 -> 14
    CCM_M16 -> 16

ccmGetL l = case l of
    CCM_L2 -> 2
    CCM_L3 -> 3
    CCM_L4 -> 4

-- | initialize a ccm context
{-# NOINLINE ccmInit #-}
ccmInit
    :: ByteArrayAccess iv
    => AES -> iv -> Int -> CCM_M -> CCM_L -> CryptoFailable AESCCM
ccmInit ctx iv n m l
    | 15 - li /= B.length iv = CryptoFailed CryptoError_IvSizeInvalid
    | otherwise = unsafeDoIO $ do
        sm <- B.alloc sizeCCM $ \ccmStPtr ->
            withKeyAndIV ctx iv $ \k v ->
                c_aes_ccm_init
                    (castPtr ccmStPtr)
                    k
                    v
                    (fromIntegral $ B.length iv)
                    (fromIntegral n)
                    (fromIntegral mi)
                    (fromIntegral li)
        return $ CryptoPassed (AESCCM sm)
  where
    mi = ccmGetM m
    li = ccmGetL l

-- | append data which is only going to be authenticated to the CCM context.
--
-- needs to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE ccmAppendAAD #-}
ccmAppendAAD :: ByteArrayAccess aad => AES -> AESCCM -> aad -> AESCCM
ccmAppendAAD ctx ccm input = unsafeDoIO $ snd <$> withCCMKeyAndCopySt ctx ccm doAppend
  where
    doAppend ccmStPtr aesPtr =
        withByteArray input $ \i -> c_aes_ccm_aad ccmStPtr aesPtr i (fromIntegral $ B.length input)

-- | append data to encrypt and append to the CCM context
--
-- the bytearray needs to be a multiple of AES block size, unless it's the last call to this function.
-- needs to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ccmEncrypt #-}
ccmEncrypt :: ByteArray ba => AES -> AESCCM -> ba -> (ba, AESCCM)
ccmEncrypt ctx ccm input = unsafeDoIO $ withCCMKeyAndCopySt ctx ccm cbcmacAndIv
  where
    len = B.length input
    cbcmacAndIv ccmStPtr aesPtr =
        B.alloc len $ \o ->
            withByteArray input $ \i ->
                c_aes_ccm_encrypt (castPtr o) ccmStPtr aesPtr i (fromIntegral len)

-- | append data to decrypt and append to the CCM context
--
-- the bytearray needs to be a multiple of AES block size, unless it's the last call to this function.
-- needs to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ccmDecrypt #-}
ccmDecrypt :: ByteArray ba => AES -> AESCCM -> ba -> (ba, AESCCM)
ccmDecrypt ctx ccm input = unsafeDoIO $ withCCMKeyAndCopySt ctx ccm cbcmacAndIv
  where
    len = B.length input
    cbcmacAndIv ccmStPtr aesPtr =
        B.alloc len $ \o ->
            withByteArray input $ \i ->
                c_aes_ccm_decrypt (castPtr o) ccmStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from CCM context
{-# NOINLINE ccmFinish #-}
ccmFinish :: AES -> AESCCM -> Int -> AuthTag
ccmFinish ctx ccm taglen = AuthTag $ B.take taglen computeTag
  where
    computeTag = B.allocAndFreeze 16 $ \t ->
        withCCMKeyAndCopySt ctx ccm (c_aes_ccm_finish (castPtr t)) >> return ()

------------------------------------------------------------------------
foreign import ccall "crypton_aes.h crypton_aes_initkey"
    c_aes_init :: Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_encrypt_ecb"
    c_aes_encrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_decrypt_ecb"
    c_aes_decrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_encrypt_cbc"
    c_aes_encrypt_cbc
        :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_decrypt_cbc"
    c_aes_decrypt_cbc
        :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_encrypt_xts"
    c_aes_encrypt_xts
        :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_decrypt_xts"
    c_aes_decrypt_xts
        :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_encrypt_ctr"
    c_aes_encrypt_ctr
        :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_encrypt_c32"
    c_aes_encrypt_c32
        :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall unsafe "crypton_aes.h crypton_aes_gcm_key_init"
    c_aes_gcm_key_init :: Ptr AESGCM -> Ptr AES -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_gcm_full_encrypt"
    c_aes_gcm_full_encrypt
        :: Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> CUInt
        -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_gcm_full_decrypt"
    c_aes_gcm_full_decrypt
        :: Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO CInt

foreign import ccall "crypton_aes.h crypton_aes_gcm_full_decrypt_tag"
    c_aes_gcm_full_decrypt_tag
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> CUInt
        -> IO ()

foreign import ccall unsafe "crypton_aes.h crypton_aes_gcm_full_decrypt_tag"
    c_aes_gcm_full_decrypt_tag_unsafe
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> CUInt
        -> IO ()

foreign import ccall unsafe "crypton_aes.h crypton_aes_gcm_full_encrypt"
    c_aes_gcm_full_encrypt_unsafe
        :: Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> CUInt
        -> IO ()

foreign import ccall unsafe "crypton_aes.h crypton_aes_gcm_full_decrypt"
    c_aes_gcm_full_decrypt_unsafe
        :: Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> IO CInt

foreign import ccall "crypton_aes.h crypton_aes_gcm_full_encrypt_mask"
    c_aes_gcm_full_encrypt_mask
        :: Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> CUInt
        -> Ptr AES
        -> CUInt
        -> Ptr Word8
        -> IO ()

foreign import ccall unsafe "crypton_aes.h crypton_aes_gcm_full_encrypt_mask"
    c_aes_gcm_full_encrypt_mask_unsafe
        :: Ptr Word8
        -> Ptr AESGCM
        -> Ptr AES
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> Ptr Word8
        -> CUInt
        -> CUInt
        -> Ptr AES
        -> CUInt
        -> Ptr Word8
        -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_gcm_init"
    c_aes_gcm_init :: Ptr AESGCM -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_gcm_aad"
    c_aes_gcm_aad :: Ptr AESGCM -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_gcm_encrypt"
    c_aes_gcm_encrypt
        :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_gcm_decrypt"
    c_aes_gcm_decrypt
        :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_gcm_finish"
    c_aes_gcm_finish :: CString -> Ptr AESGCM -> Ptr AES -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ocb_init"
    c_aes_ocb_init
        :: Ptr AESOCB -> Ptr AES -> Ptr Word8 -> CUInt -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ocb_aad"
    c_aes_ocb_aad :: Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ocb_encrypt"
    c_aes_ocb_encrypt
        :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ocb_decrypt"
    c_aes_ocb_decrypt
        :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ocb_finish"
    c_aes_ocb_finish :: CString -> Ptr AESOCB -> Ptr AES -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ccm_init"
    c_aes_ccm_init
        :: Ptr AESCCM -> Ptr AES -> Ptr Word8 -> CUInt -> CUInt -> CInt -> CInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ccm_aad"
    c_aes_ccm_aad :: Ptr AESCCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ccm_encrypt"
    c_aes_ccm_encrypt
        :: CString -> Ptr AESCCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ccm_decrypt"
    c_aes_ccm_decrypt
        :: CString -> Ptr AESCCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "crypton_aes.h crypton_aes_ccm_finish"
    c_aes_ccm_finish :: CString -> Ptr AESCCM -> Ptr AES -> IO ()
