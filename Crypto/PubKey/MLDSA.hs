-- |
-- Module      : Crypto.PubKey.MLDSA
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- ML-DSA, the Module-Lattice-Based Digital Signature Algorithm of
-- <https://csrc.nist.gov/pubs/fips/204/final FIPS 204>, in all three
-- parameter sets.
--
-- > (vk, sk) <- generateKeyPair MLDSA65
-- > sig      <- sign sk noContext message
-- > verify vk noContext message sig
--
-- The parameter set is a type, so an ML-DSA-65 key cannot be passed where
-- an ML-DSA-87 one is expected.  The three are fixed by FIPS 204 and the
-- class has no other instances.
--
-- This is pure ML-DSA: the message goes in whole.  The pre-hash variant
-- (HashML-DSA) is a different algorithm with a different domain separator
-- and is not offered here.
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.PubKey.MLDSA (
    -- * Parameter sets
    MLDSA44 (..),
    MLDSA65 (..),
    MLDSA87 (..),
    MLDSA (verificationKeySize, signingKeySize, signatureSize),

    -- * Keys and signatures
    VerificationKey,
    SigningKey,
    Signature,

    -- * Smart constructors
    verificationKey,
    signingKey,
    signature,

    -- * Generating a key pair
    generateKeyPair,
    keyPairFromSeed,
    toPublic,

    -- * The context string
    Context,
    context,
    noContext,

    -- * The message representative
    Mu,
    mu,
    messageRepresentative,

    -- * Signing and verifying
    sign,
    signWith,
    signDeterministic,
    verify,

    -- * Signing and verifying a message representative
    signExternalMu,
    signExternalMuWith,
    signExternalMuDeterministic,
    verifyExternalMu,

    -- * Sizes
    seedSize,
    signingRandomnessSize,
    maxContextLength,
    muSize,
) where

import Data.Proxy (Proxy (..))
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr, nullPtr)

import Crypto.Debug (DebugShow (..), debugShowBytes)
import Crypto.Hash (Digest, hash)
import Crypto.Hash.Algorithms (SHAKE256 (..))
import Crypto.Error
import Crypto.Internal.ByteArray (
    ByteArrayAccess,
    Bytes,
    ScrubbedBytes,
    withByteArray,
 )
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Internal.Imports
import Crypto.Random (MonadRandom, getRandomBytes)

-- | ML-DSA-44.
data MLDSA44 = MLDSA44 deriving (Show, Eq)

-- | ML-DSA-65.
data MLDSA65 = MLDSA65 deriving (Show, Eq)

-- | ML-DSA-87.
data MLDSA87 = MLDSA87 deriving (Show, Eq)

-- | The three parameter sets of FIPS 204.
--
-- Named for the algorithm rather than \"DSA\", which is a different one that
-- crypton also has, in "Crypto.PubKey.DSA".  It is the three sets FIPS 204
-- defines, closed, carrying their sizes and the calls into the
-- implementation; only the sizes are exported.
class MLDSA p where
    -- | Size in bytes of a 'VerificationKey' of this parameter set.
    verificationKeySize :: proxy p -> Int

    -- | Size in bytes of a 'SigningKey' of this parameter set.
    signingKeySize :: proxy p -> Int

    -- | Size in bytes of a 'Signature' of this parameter set.
    signatureSize :: proxy p -> Int

    c_keypair :: proxy p -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
    c_sign
        :: proxy p
        -> Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> Ptr Word8 -> CInt -> IO CInt
    c_verify
        :: proxy p
        -> Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> CInt -> IO CInt
    c_pkFromSk :: proxy p -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- | A public verification key.
newtype VerificationKey p = VerificationKey Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | A private signing key.
newtype SigningKey p = SigningKey ScrubbedBytes
    deriving (Eq, ByteArrayAccess, NFData)

instance Show (SigningKey p) where
    show _ = "SigningKey <redacted>"

instance DebugShow (SigningKey p) where
    debugShow = debugShowBytes "SigningKey"

-- | A signature.
newtype Signature p = Signature Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | The context string a signature is bound to, at most
-- 'maxContextLength' bytes.
--
-- FIPS 204 mixes it into what is signed, so a signature made under one
-- context does not verify under another.  Two uses of one key that agree on
-- a context string cannot be made to accept each other's signatures.  Use
-- 'noContext' where there is nothing to separate -- TLS, for one, signs
-- with an empty context.
newtype Context = Context Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | The empty context.
noContext :: Context
noContext = Context B.empty

-- | Try to build a context string.
context :: ByteArrayAccess ba => ba -> CryptoFailable Context
context bs
    | B.length bs <= maxContextLength =
        CryptoPassed $ Context $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise = CryptoFailed CryptoError_ParameterInvalid

-- | The longest context string FIPS 204 allows, which is 255 bytes because
-- its length is encoded in one byte.
maxContextLength :: Int
maxContextLength = 255

-- | The message representative, @mu@ in FIPS 204: a 64-byte commitment to
-- the verification key, the context string and the message, and the only
-- part of them that signing and verification actually read.
--
-- Signing it directly is the "external mu" interface.  It is for a caller
-- that has the representative without having the message in one piece: a
-- message arriving as a stream, or hashed on another machine, or by a
-- device that holds the key and is handed only this.  TLS does not need it.
newtype Mu = Mu Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | Size in bytes of a 'Mu'.
muSize :: Int
muSize = 64

-- | Try to read a message representative.
mu :: ByteArrayAccess ba => ba -> CryptoFailable Mu
mu bs
    | B.length bs == muSize = CryptoPassed $ Mu $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise = CryptoFailed CryptoError_ParameterInvalid

-- | Compute the message representative, for a caller that wants to make it
-- here and sign it later, or sign it elsewhere.
--
-- @'signExternalMuDeterministic' sk ('messageRepresentative' ('toPublic' sk) ctx msg)@
-- and @'signDeterministic' sk ctx msg@ are the same signature.
messageRepresentative
    :: (MLDSA p, ByteArrayAccess msg)
    => VerificationKey p -> Context -> msg -> Mu
messageRepresentative vk ctx msg = Mu (B.convert d)
  where
    -- FIPS 204: tr <- H(pk, 64) at key generation, and mu <- H(tr || M', 64)
    -- when signing, with M' the domain-separated message.
    tr = B.convert (shake64 (B.convert vk :: Bytes)) :: Bytes
    d = shake64 (B.concat [tr, domainPrefix ctx, B.convert msg] :: Bytes)

shake64 :: ByteArrayAccess ba => ba -> Digest (SHAKE256 512)
shake64 = hash

-- | Size in bytes of the seed 'keyPairFromSeed' takes, @xi@ in FIPS 204.
seedSize :: Int
seedSize = 32

-- | Size in bytes of the randomness 'signWith' takes.
signingRandomnessSize :: Int
signingRandomnessSize = 32

-- | Try to read a verification key.  Only the length is checked: a
-- verification key is a packed encoding with no redundancy to test, and one
-- that is not a real key simply verifies nothing.
verificationKey
    :: forall p ba
     . (MLDSA p, ByteArrayAccess ba)
    => ba -> CryptoFailable (VerificationKey p)
verificationKey bs
    | B.length bs == verificationKeySize (Proxy :: Proxy p) =
        CryptoPassed $ VerificationKey $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise = CryptoFailed CryptoError_PublicKeySizeInvalid

-- | Try to read a signing key.
--
-- Beyond the length this runs the validity checks of the implementation:
-- the secret polynomials must have coefficients in range, and the
-- commitment and the public-key hash the key carries must match what is
-- recomputed from the rest of it.  A key that fails has been damaged or was
-- never a key, and signing with it would produce signatures nothing
-- verifies.
signingKey
    :: forall p ba
     . (MLDSA p, ByteArrayAccess ba)
    => ba -> CryptoFailable (SigningKey p)
signingKey bs
    | B.length bs /= signingKeySize p = CryptoFailed CryptoError_SecretKeySizeInvalid
    | otherwise = unsafeDoIO $ do
        (r, _ :: Bytes) <- B.allocRet (verificationKeySize p) $ \ppk ->
            withByteArray bs $ \psk -> c_pkFromSk p ppk psk
        return $
            if r == 0
                then CryptoPassed $ SigningKey $ B.copyAndFreeze bs (\_ -> return ())
                else CryptoFailed CryptoError_SecretKeyStructureInvalid
  where
    p = Proxy :: Proxy p
{-# NOINLINE signingKey #-}

-- | Try to read a signature.  Only the length is checked; whether it is a
-- signature of anything is what 'verify' answers.
signature
    :: forall p ba
     . (MLDSA p, ByteArrayAccess ba)
    => ba -> CryptoFailable (Signature p)
signature bs
    | B.length bs == signatureSize (Proxy :: Proxy p) =
        CryptoPassed $ Signature $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise = CryptoFailed CryptoError_ParameterInvalid

-- | Recover the verification key a signing key was made with.
toPublic :: forall p. MLDSA p => SigningKey p -> VerificationKey p
toPublic sk = VerificationKey $ unsafeDoIO $ do
    (_ :: CInt, pk) <- B.allocRet (verificationKeySize p) $ \ppk ->
        withByteArray sk $ \psk -> c_pkFromSk p ppk psk
    return pk
  where
    p = Proxy :: Proxy p
{-# NOINLINE toPublic #-}

-- | Generate a key pair.
generateKeyPair
    :: forall p proxy m
     . (MLDSA p, MonadRandom m)
    => proxy p -> m (VerificationKey p, SigningKey p)
generateKeyPair p = do
    seed <- getRandomBytes seedSize :: m ScrubbedBytes
    case keyPairFromSeed p seed of
        CryptoPassed r -> return r
        CryptoFailed e -> error ("Crypto.PubKey.MLDSA.generateKeyPair: " ++ show e)

-- | Derive a key pair from a seed, @xi@ in FIPS 204, which must be
-- 'seedSize' bytes.
keyPairFromSeed
    :: forall p proxy ba
     . (MLDSA p, ByteArrayAccess ba)
    => proxy p -> ba -> CryptoFailable (VerificationKey p, SigningKey p)
keyPairFromSeed p seed
    | B.length seed /= seedSize = CryptoFailed CryptoError_SeedSizeInvalid
    | otherwise = unsafeDoIO $ do
        -- Not zeroed, and does not need to be: the C writes the whole
        -- buffer, and on a non-zero return the result is discarded without
        -- being read.  Anything that is *read* before being written has to
        -- use B.zero instead -- see signInternal in Crypto.PubKey.MLDSA.
        sk <- B.alloc (signingKeySize p) (\_ -> return ()) :: IO ScrubbedBytes
        (r, vk) <- B.allocRet (verificationKeySize p) $ \pvk ->
            withByteArray sk $ \psk ->
                withByteArray seed $ \pseed ->
                    c_keypair p pvk psk pseed
        return $
            if r == 0
                then CryptoPassed (VerificationKey vk, SigningKey sk)
                else CryptoFailed CryptoError_ParameterInvalid
{-# NOINLINE keyPairFromSeed #-}

-- | Sign a message.
--
-- This is the hedged signing FIPS 204 recommends: fresh randomness goes in
-- alongside the key and the message, so two signatures of one message
-- differ and a fault in one reveals less.  Verification does not care which
-- of the three entry points made the signature.
sign
    :: forall p m msg
     . (MLDSA p, MonadRandom m, ByteArrayAccess msg)
    => SigningKey p -> Context -> msg -> m (Signature p)
sign sk ctx msg = do
    rnd <- getRandomBytes signingRandomnessSize :: m ScrubbedBytes
    case signWith sk ctx msg rnd of
        CryptoPassed s -> return s
        CryptoFailed e -> error ("Crypto.PubKey.MLDSA.sign: " ++ show e)

-- | Sign with the randomness supplied, which must be
-- 'signingRandomnessSize' bytes.
--
-- For test vectors, and for callers who draw their own randomness.  Ordinary
-- use wants 'sign'.
signWith
    :: forall p msg rnd
     . (MLDSA p, ByteArrayAccess msg, ByteArrayAccess rnd)
    => SigningKey p -> Context -> msg -> rnd -> CryptoFailable (Signature p)
signWith sk ctx msg rnd
    | B.length rnd /= signingRandomnessSize = CryptoFailed CryptoError_SeedSizeInvalid
    | otherwise = signInternal sk ctx msg (Just rnd)

-- | Sign deterministically, as FIPS 204 section 3.4 allows: the randomness
-- is replaced by zeroes, so one key and one message always give one
-- signature.
--
-- This is what test vectors are written against, and what to use where the
-- signature must be reproducible.  It gives up what hedging buys, so where
-- there is a usable random source 'sign' is the better default.
signDeterministic
    :: forall p msg
     . (MLDSA p, ByteArrayAccess msg)
    => SigningKey p -> Context -> msg -> Signature p
signDeterministic sk ctx msg =
    case signInternal sk ctx msg (Nothing :: Maybe Bytes) of
        CryptoPassed s -> s
        CryptoFailed e -> error ("Crypto.PubKey.MLDSA.signDeterministic: " ++ show e)

signInternal
    :: forall p msg rnd
     . (MLDSA p, ByteArrayAccess msg, ByteArrayAccess rnd)
    => SigningKey p -> Context -> msg -> Maybe rnd -> CryptoFailable (Signature p)
signInternal sk ctx msg mrnd = unsafeDoIO $ do
    -- B.zero, not B.alloc with an empty action: alloc hands back whatever
    -- was in the memory.  That made signDeterministic sign with the last
    -- caller's bytes and produce a different signature every time, which the
    -- ACVP vectors caught only once the whole suite ran and the allocator
    -- stopped handing out fresh zeroed pages.
    let zeroes = B.zero signingRandomnessSize :: ScrubbedBytes
        withRnd f = case mrnd of
            Just r -> withByteArray r f
            Nothing -> withByteArray zeroes f
    (r, sig) <- B.allocRet (signatureSize p) $ \psig ->
        withByteArray msg $ \pmsg ->
            withByteArray pre $ \ppre ->
                withRnd $ \prnd ->
                    withByteArray sk $ \psk ->
                        c_sign
                            p
                            psig
                            pmsg
                            (fromIntegral (B.length msg))
                            ppre
                            (fromIntegral (B.length pre))
                            prnd
                            psk
                            0
    return $
        if r == 0
            then CryptoPassed (Signature sig)
            else CryptoFailed CryptoError_ParameterInvalid
  where
    p = Proxy :: Proxy p
    pre = domainPrefix ctx
{-# NOINLINE signInternal #-}

-- | Sign a message representative, drawing the randomness.
--
-- The context string is already inside the representative, which is why
-- this does not take one.
signExternalMu
    :: forall p m
     . (MLDSA p, MonadRandom m)
    => SigningKey p -> Mu -> m (Signature p)
signExternalMu sk m = do
    rnd <- getRandomBytes signingRandomnessSize :: m ScrubbedBytes
    case signExternalMuWith sk m rnd of
        CryptoPassed s -> return s
        CryptoFailed e -> error ("Crypto.PubKey.MLDSA.signExternalMu: " ++ show e)

-- | Sign a message representative with the randomness supplied.
signExternalMuWith
    :: (MLDSA p, ByteArrayAccess rnd)
    => SigningKey p -> Mu -> rnd -> CryptoFailable (Signature p)
signExternalMuWith sk m rnd
    | B.length rnd /= signingRandomnessSize = CryptoFailed CryptoError_SeedSizeInvalid
    | otherwise = signMu sk m (Just rnd)

-- | Sign a message representative deterministically.
signExternalMuDeterministic
    :: MLDSA p => SigningKey p -> Mu -> Signature p
signExternalMuDeterministic sk m =
    case signMu sk m (Nothing :: Maybe Bytes) of
        CryptoPassed s -> s
        CryptoFailed e ->
            error ("Crypto.PubKey.MLDSA.signExternalMuDeterministic: " ++ show e)

-- | Verify a signature of a message representative.
verifyExternalMu
    :: forall p. MLDSA p => VerificationKey p -> Mu -> Signature p -> Bool
verifyExternalMu vk m sig
    | B.length sig /= signatureSize p = False
    | otherwise = unsafeDoIO $
        withByteArray sig $ \psig ->
            withByteArray m $ \pmu ->
                withByteArray vk $ \pvk -> do
                    r <-
                        c_verify
                            p
                            psig
                            pmu
                            (fromIntegral muSize)
                            nullPtr
                            0
                            pvk
                            1
                    return (r == 0)
  where
    p = Proxy :: Proxy p
{-# NOINLINE verifyExternalMu #-}

-- The external-mu entry points are the ordinary ones with the last argument
-- set: the representative goes in where the message would, there is no
-- domain separation prefix to prepend because it is already inside, and the
-- implementation is told so.
signMu
    :: forall p rnd
     . (MLDSA p, ByteArrayAccess rnd)
    => SigningKey p -> Mu -> Maybe rnd -> CryptoFailable (Signature p)
signMu sk m mrnd = unsafeDoIO $ do
    let zeroes = B.zero signingRandomnessSize :: ScrubbedBytes
        withRnd f = case mrnd of
            Just r -> withByteArray r f
            Nothing -> withByteArray zeroes f
    (r, sig) <- B.allocRet (signatureSize p) $ \psig ->
        withByteArray m $ \pmu ->
            withRnd $ \prnd ->
                withByteArray sk $ \psk ->
                    c_sign p psig pmu (fromIntegral muSize) nullPtr 0 prnd psk 1
    return $
        if r == 0
            then CryptoPassed (Signature sig)
            else CryptoFailed CryptoError_ParameterInvalid
  where
    p = Proxy :: Proxy p
{-# NOINLINE signMu #-}

-- | Verify a signature.
--
-- The context must be the one it was signed under; anything else is a
-- rejection, which is what the context is for.
verify
    :: forall p msg
     . (MLDSA p, ByteArrayAccess msg)
    => VerificationKey p -> Context -> msg -> Signature p -> Bool
verify vk ctx msg sig
    | B.length sig /= signatureSize p = False
    | otherwise = unsafeDoIO $
        withByteArray sig $ \psig ->
            withByteArray msg $ \pmsg ->
                withByteArray pre $ \ppre ->
                    withByteArray vk $ \pvk -> do
                        r <-
                            c_verify
                                p
                                psig
                                pmsg
                                (fromIntegral (B.length msg))
                                ppre
                                (fromIntegral (B.length pre))
                                pvk
                                0
                        return (r == 0)
  where
    p = Proxy :: Proxy p
    pre = domainPrefix ctx
{-# NOINLINE verify #-}

-- | The domain separation prefix of FIPS 204 for pure ML-DSA, which is a
-- zero byte, the context's length and the context itself.  It is built here
-- rather than taken from the implementation because it is three bytes of
-- concatenation and doing it here keeps one fewer foreign call.
domainPrefix :: Context -> Bytes
domainPrefix (Context ctx) =
    B.concat [B.pack [0, fromIntegral (B.length ctx)] :: Bytes, B.convert ctx]

instance MLDSA MLDSA44 where
    verificationKeySize _ = 1312
    signingKeySize _ = 2560
    signatureSize _ = 2420
    c_keypair _ = c_mldsa44_keypair
    c_sign _ = c_mldsa44_sign
    c_verify _ = c_mldsa44_verify
    c_pkFromSk _ = c_mldsa44_pk_from_sk

instance MLDSA MLDSA65 where
    verificationKeySize _ = 1952
    signingKeySize _ = 4032
    signatureSize _ = 3309
    c_keypair _ = c_mldsa65_keypair
    c_sign _ = c_mldsa65_sign
    c_verify _ = c_mldsa65_verify
    c_pkFromSk _ = c_mldsa65_pk_from_sk

instance MLDSA MLDSA87 where
    verificationKeySize _ = 2592
    signingKeySize _ = 4896
    signatureSize _ = 4627
    c_keypair _ = c_mldsa87_keypair
    c_sign _ = c_mldsa87_sign
    c_verify _ = c_mldsa87_verify
    c_pkFromSk _ = c_mldsa87_pk_from_sk

foreign import ccall unsafe "crypton_mldsa44_keypair_internal"
    c_mldsa44_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mldsa44_signature_internal"
    c_mldsa44_sign
        :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "crypton_mldsa44_verify_internal"
    c_mldsa44_verify
        :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "crypton_mldsa44_pk_from_sk"
    c_mldsa44_pk_from_sk :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypton_mldsa65_keypair_internal"
    c_mldsa65_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mldsa65_signature_internal"
    c_mldsa65_sign
        :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "crypton_mldsa65_verify_internal"
    c_mldsa65_verify
        :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "crypton_mldsa65_pk_from_sk"
    c_mldsa65_pk_from_sk :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypton_mldsa87_keypair_internal"
    c_mldsa87_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mldsa87_signature_internal"
    c_mldsa87_sign
        :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "crypton_mldsa87_verify_internal"
    c_mldsa87_verify
        :: Ptr Word8 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize
        -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "crypton_mldsa87_pk_from_sk"
    c_mldsa87_pk_from_sk :: Ptr Word8 -> Ptr Word8 -> IO CInt
