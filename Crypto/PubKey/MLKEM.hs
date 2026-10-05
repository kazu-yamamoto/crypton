-- |
-- Module      : Crypto.PubKey.MLKEM
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- ML-KEM, the Module-Lattice-Based Key-Encapsulation Mechanism of
-- <https://csrc.nist.gov/pubs/fips/203/final FIPS 203>, in all three
-- parameter sets.
--
-- A key encapsulation mechanism is not a Diffie-Hellman: there is no shared
-- secret to be computed from two key pairs.  One side publishes an
-- 'EncapsulationKey'; the other calls 'encapsulate' on it, which draws a
-- fresh secret and returns it along with a 'Ciphertext' that only the holder
-- of the matching 'DecapsulationKey' can turn back into that secret.
--
-- > (ek, dk)  <- generateKeyPair MLKEM768        -- the receiver
-- > (ct, ss)  <- encapsulate ek                  -- the sender
-- > let ss'   =  decapsulate dk ct               -- the receiver, again
-- > ss == ss'
--
-- The parameter set is a type, so an ML-KEM-768 key cannot be passed where
-- an ML-KEM-1024 one is expected.  The three are fixed by FIPS 203 and the
-- class has no other instances.
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableSuperClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.PubKey.MLKEM (
    -- * Parameter sets
    MLKEM512 (..),
    MLKEM768 (..),
    MLKEM1024 (..),
    MLKEM (encapsulationKeySize, decapsulationKeySize, ciphertextSize),

    -- * Keys, ciphertexts and shared secrets
    --
    -- | These are the associated types of 'KEM', re-exported so that a
    -- caller of this module alone has them.
    KEM (..),
    SharedSecret (..),

    -- * Smart constructors
    encapsulationKey,
    decapsulationKey,
    ciphertext,

    -- * What ML-KEM has beyond the class
    generateKeyPairAndSeed,
    keyPairFromSeed,
    encapsulateWith,

    -- * Sizes
    seedSize,
    encapsulationCoinsSize,
    sharedSecretSize,
) where

import Data.Proxy (Proxy (..))
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)

import Crypto.Debug (DebugShow (..), debugShowBytes)
import Crypto.Error
import Crypto.KEM
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

-- | ML-KEM-512.
data MLKEM512 = MLKEM512 deriving (Show, Eq)

-- | ML-KEM-768.  This is the set TLS uses, on its own and as the
-- lattice half of the hybrid groups.
data MLKEM768 = MLKEM768 deriving (Show, Eq)

-- | ML-KEM-1024.
data MLKEM1024 = MLKEM1024 deriving (Show, Eq)

-- | The three parameter sets of FIPS 203.
--
-- This is not an abstract KEM interface and does not try to be: it is the
-- three sets FIPS 203 defines, closed, carrying their sizes and the calls
-- into the implementation.  Only the sizes are exported.  If crypton grows
-- a second KEM and an interface common to both is wanted, that belongs in
-- a module of its own, with this as one of its instances.
class
    ( KEM p
    , EncapsulationKey p ~ MLKEMEncapsulationKey p
    , DecapsulationKey p ~ MLKEMDecapsulationKey p
    , Ciphertext p ~ MLKEMCiphertext p
    ) =>
    MLKEM p
    where
    -- | Size in bytes of an 'EncapsulationKey' of this parameter set.
    encapsulationKeySize :: proxy p -> Int

    -- | Size in bytes of a 'DecapsulationKey' of this parameter set.
    decapsulationKeySize :: proxy p -> Int

    -- | Size in bytes of a 'Ciphertext' of this parameter set.
    ciphertextSize :: proxy p -> Int

    c_keypair :: proxy p -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
    c_enc :: proxy p -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
    c_dec :: proxy p -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
    c_checkPk :: proxy p -> Ptr Word8 -> IO CInt
    c_checkSk :: proxy p -> Ptr Word8 -> IO CInt

-- | A public encapsulation key, @ek@ in FIPS 203.
newtype MLKEMEncapsulationKey p = MLKEMEncapsulationKey Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | A private decapsulation key, @dk@ in FIPS 203.  It embeds the matching
-- encapsulation key, which is why it is the larger of the two.
newtype MLKEMDecapsulationKey p = MLKEMDecapsulationKey ScrubbedBytes
    deriving (Eq, ByteArrayAccess, NFData)

instance Show (MLKEMDecapsulationKey p) where
    show _ = "DecapsulationKey <redacted>"

instance DebugShow (MLKEMDecapsulationKey p) where
    debugShow = debugShowBytes "DecapsulationKey"

-- | The value 'encapsulate' produces and 'decapsulate' consumes.
newtype MLKEMCiphertext p = MLKEMCiphertext Bytes
    deriving (Show, Eq, ByteArrayAccess, NFData)

-- | Size in bytes of the seed 'keyPairFromSeed' takes, which is @d@ and @z@
-- of FIPS 203 one after the other.
seedSize :: Int
seedSize = 64

-- | Size in bytes of the randomness 'encapsulateWith' takes, @m@ in
-- FIPS 203.
encapsulationCoinsSize :: Int
encapsulationCoinsSize = 32

-- | Size in bytes of a 'SharedSecret'.
sharedSecretSize :: Int
sharedSecretSize = 32

-- | Try to read an encapsulation key.
--
-- Beyond the length this runs the check of FIPS 203 section 7.2: the key
-- must be the encoding of coefficients that are all in range, which is to
-- say it must survive a decode and re-encode unchanged.  A key that fails
-- it is not one any honest party produced.
encapsulationKey
    :: forall p ba
     . (MLKEM p, ByteArrayAccess ba)
    => ba -> CryptoFailable (EncapsulationKey p)
encapsulationKey bs
    | B.length bs /= encapsulationKeySize p = CryptoFailed CryptoError_PublicKeySizeInvalid
    | otherwise = unsafeDoIO $ withByteArray bs $ \inp -> do
        r <- c_checkPk p inp
        return $
            if r == 0
                then CryptoPassed $ MLKEMEncapsulationKey $ B.copyAndFreeze bs (\_ -> return ())
                else CryptoFailed CryptoError_PublicKeyStructureInvalid
  where
    p = Proxy :: Proxy p
{-# NOINLINE encapsulationKey #-}

-- | Try to read a decapsulation key.
--
-- Beyond the length this runs the check of FIPS 203 section 7.3: the hash
-- of the encapsulation key the private key embeds must match the copy of
-- that hash it also embeds.  The two disagreeing means the key was not
-- produced as a pair, and decapsulating with it would silently answer with
-- the implicit rejection every time.
decapsulationKey
    :: forall p ba
     . (MLKEM p, ByteArrayAccess ba)
    => ba -> CryptoFailable (DecapsulationKey p)
decapsulationKey bs
    | B.length bs /= decapsulationKeySize p = CryptoFailed CryptoError_SecretKeySizeInvalid
    | otherwise = unsafeDoIO $ withByteArray bs $ \inp -> do
        r <- c_checkSk p inp
        return $
            if r == 0
                then CryptoPassed $ MLKEMDecapsulationKey $ B.copyAndFreeze bs (\_ -> return ())
                else CryptoFailed CryptoError_SecretKeyStructureInvalid
  where
    p = Proxy :: Proxy p
{-# NOINLINE decapsulationKey #-}

-- | Try to read a ciphertext.  Only the length is checked; every string of
-- the right length is a ciphertext that 'decapsulate' will answer.
ciphertext
    :: forall p ba
     . (MLKEM p, ByteArrayAccess ba)
    => ba -> CryptoFailable (Ciphertext p)
ciphertext bs
    | B.length bs == ciphertextSize (Proxy :: Proxy p) =
        CryptoPassed $ MLKEMCiphertext $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise = CryptoFailed CryptoError_PointSizeInvalid

-- | Generate a key pair.
--
-- The seed it is derived from is drawn here and thrown away.  Use
-- 'generateKeyPairAndSeed' where it has to be kept.
mlkemGenerateKeyPair
    :: forall p proxy m
     . (MLKEM p, MonadRandom m)
    => proxy p -> m (MLKEMEncapsulationKey p, DecapsulationKey p)
mlkemGenerateKeyPair p = do
    (ek, dk, _) <- generateKeyPairAndSeed p
    return (ek, dk)

-- | Generate a key pair and hand back the seed it was derived from, @d@
-- and @z@ of FIPS 203 one after the other.
--
-- A 'DecapsulationKey' is the expanded key and nothing else, so the seed
-- cannot be recovered from a pair afterwards.  An application that has to
-- write the key out in a form that keeps the seed has to generate it here:
--
-- > (ek, dk, seed) <- generateKeyPairAndSeed MLKEM768
--
-- The seed is as secret as the decapsulation key: 'keyPairFromSeed' turns
-- it back into the same pair.
generateKeyPairAndSeed
    :: forall p proxy m
     . (MLKEM p, MonadRandom m)
    => proxy p
    -> m (MLKEMEncapsulationKey p, DecapsulationKey p, ScrubbedBytes)
generateKeyPairAndSeed p = do
    seed <- getRandomBytes seedSize :: m ScrubbedBytes
    case keyPairFromSeed p seed of
        CryptoPassed (ek, dk) -> return (ek, dk, seed)
        CryptoFailed e ->
            error ("Crypto.PubKey.MLKEM.generateKeyPairAndSeed: " ++ show e)

-- | Derive a key pair from a seed, which is @d@ and @z@ of FIPS 203 one
-- after the other and must be 'seedSize' bytes.
--
-- This is the entry point to use when the seed comes from somewhere
-- particular -- a test vector, or a store that keeps seeds rather than
-- expanded keys.  For an ordinary key, 'generateKeyPair' draws the seed
-- itself.
keyPairFromSeed
    :: forall p proxy ba
     . (MLKEM p, ByteArrayAccess ba)
    => proxy p
    -> ba
    -> CryptoFailable (MLKEMEncapsulationKey p, DecapsulationKey p)
keyPairFromSeed p seed
    | B.length seed /= seedSize = CryptoFailed CryptoError_SeedSizeInvalid
    | otherwise = unsafeDoIO $ do
        -- Not zeroed, and does not need to be: the C writes the whole
        -- buffer, and on a non-zero return the result is discarded without
        -- being read.  Anything that is *read* before being written has to
        -- use B.zero instead -- see signInternal in Crypto.PubKey.MLDSA.
        dk <- B.alloc (decapsulationKeySize p) (\_ -> return ()) :: IO ScrubbedBytes
        (r, ek) <- B.allocRet (encapsulationKeySize p) $ \pek ->
            withByteArray dk $ \pdk ->
                withByteArray seed $ \pseed ->
                    c_keypair p pek pdk pseed
        return $
            if r == 0
                then CryptoPassed (MLKEMEncapsulationKey ek, MLKEMDecapsulationKey dk)
                else CryptoFailed CryptoError_ParameterInvalid
{-# NOINLINE keyPairFromSeed #-}

-- | Encapsulate against a public key, drawing the randomness.
mlkemEncapsulate
    :: forall p m
     . (MLKEM p, MonadRandom m)
    => MLKEMEncapsulationKey p
    -> m (CryptoFailable (Ciphertext p, SharedSecret))
mlkemEncapsulate ek = do
    coins <- getRandomBytes encapsulationCoinsSize :: m ScrubbedBytes
    return (encapsulateWith ek coins)

-- | Encapsulate with randomness supplied, which is @m@ of FIPS 203 and must
-- be 'encapsulationCoinsSize' bytes.
--
-- The secret this produces is a deterministic function of the key and these
-- bytes, so they must come from a source no other party can predict or
-- repeat.  'encapsulate' is the entry point for ordinary use; this one is
-- for test vectors and for callers who are deliberately supplying their own.
encapsulateWith
    :: forall p ba
     . (MLKEM p, ByteArrayAccess ba)
    => EncapsulationKey p -> ba -> CryptoFailable (Ciphertext p, SharedSecret)
encapsulateWith ek coins
    | B.length coins /= encapsulationCoinsSize = CryptoFailed CryptoError_SeedSizeInvalid
    | otherwise = unsafeDoIO $ do
        ss <- B.alloc sharedSecretSize (\_ -> return ()) :: IO ScrubbedBytes
        (r, ct) <- B.allocRet (ciphertextSize p) $ \pct ->
            withByteArray ss $ \pss ->
                withByteArray ek $ \pek ->
                    withByteArray coins $ \pcoins ->
                        c_enc p pct pss pek pcoins
        return $
            if r == 0
                then CryptoPassed (MLKEMCiphertext ct, SharedSecret ss)
                else CryptoFailed CryptoError_ParameterInvalid
  where
    p = Proxy :: Proxy p
{-# NOINLINE encapsulateWith #-}

-- | Recover the shared secret from a ciphertext.
--
-- A ciphertext that was not produced by encapsulating against the matching
-- key is not an error.  ML-KEM rejects implicitly: it yields a secret
-- derived from the private key and the ciphertext, and the caller cannot
-- tell that case from the other one, which is the point -- telling them
-- apart is what a chosen-ciphertext attack needs.  A ciphertext that does
-- not belong here shows up later, as the two sides failing to agree on
-- anything.
--
-- The checks FIPS 203 does require are at the point where bytes become a
-- value of these types, which is where they can be reported:
--
-- * The ciphertext type check of section 7.3 is its length, and
--   'ciphertext' is the only way to build a 'Ciphertext' from bytes.  There
--   is nothing else to check: a ciphertext's coefficients are compressed to
--   fewer than twelve bits, so every bit pattern decodes to a value in
--   range.
-- * The hash check of section 7.3 is on the decapsulation key, and
--   'decapsulationKey' runs it; a key from 'generateKeyPair' or
--   'keyPairFromSeed' satisfies it by construction.
--
-- So the result is 'CryptoPassed' for every key and ciphertext this module
-- can produce.  It is 'CryptoFailable' rather than a bare 'SharedSecret'
-- because the implementation checks the key again on its way through, and
-- what it finds is better reported than turned into an exception.
mlkemDecapsulate
    :: forall p
     . MLKEM p
    => DecapsulationKey p -> Ciphertext p -> CryptoFailable SharedSecret
mlkemDecapsulate dk ct = unsafeDoIO $ do
    (r, ss) <- B.allocRet sharedSecretSize $ \pss ->
        withByteArray ct $ \pct ->
            withByteArray dk $ \pdk ->
                c_dec (Proxy :: Proxy p) pss pct pdk
    return $
        if r == (0 :: CInt)
            then CryptoPassed (SharedSecret ss)
            else CryptoFailed CryptoError_SecretKeyStructureInvalid
{-# NOINLINE mlkemDecapsulate #-}

-- The class's view of the three sets.  The operations are the ones above;
-- only the shape of the arguments differs, because the class takes the
-- mechanism as a proxy.
instance KEM MLKEM512 where
    type EncapsulationKey MLKEM512 = MLKEMEncapsulationKey MLKEM512
    type DecapsulationKey MLKEM512 = MLKEMDecapsulationKey MLKEM512
    type Ciphertext MLKEM512 = MLKEMCiphertext MLKEM512
    generateKeyPair = mlkemGenerateKeyPair
    encapsulate _ = mlkemEncapsulate
    decapsulate _ = mlkemDecapsulate

instance KEM MLKEM768 where
    type EncapsulationKey MLKEM768 = MLKEMEncapsulationKey MLKEM768
    type DecapsulationKey MLKEM768 = MLKEMDecapsulationKey MLKEM768
    type Ciphertext MLKEM768 = MLKEMCiphertext MLKEM768
    generateKeyPair = mlkemGenerateKeyPair
    encapsulate _ = mlkemEncapsulate
    decapsulate _ = mlkemDecapsulate

instance KEM MLKEM1024 where
    type EncapsulationKey MLKEM1024 = MLKEMEncapsulationKey MLKEM1024
    type DecapsulationKey MLKEM1024 = MLKEMDecapsulationKey MLKEM1024
    type Ciphertext MLKEM1024 = MLKEMCiphertext MLKEM1024
    generateKeyPair = mlkemGenerateKeyPair
    encapsulate _ = mlkemEncapsulate
    decapsulate _ = mlkemDecapsulate

instance MLKEM MLKEM512 where
    encapsulationKeySize _ = 800
    decapsulationKeySize _ = 1632
    ciphertextSize _ = 768
    c_keypair _ = c_mlkem512_keypair
    c_enc _ = c_mlkem512_enc
    c_dec _ = c_mlkem512_dec
    c_checkPk _ = c_mlkem512_check_pk
    c_checkSk _ = c_mlkem512_check_sk

instance MLKEM MLKEM768 where
    encapsulationKeySize _ = 1184
    decapsulationKeySize _ = 2400
    ciphertextSize _ = 1088
    c_keypair _ = c_mlkem768_keypair
    c_enc _ = c_mlkem768_enc
    c_dec _ = c_mlkem768_dec
    c_checkPk _ = c_mlkem768_check_pk
    c_checkSk _ = c_mlkem768_check_sk

instance MLKEM MLKEM1024 where
    encapsulationKeySize _ = 1568
    decapsulationKeySize _ = 3168
    ciphertextSize _ = 1568
    c_keypair _ = c_mlkem1024_keypair
    c_enc _ = c_mlkem1024_enc
    c_dec _ = c_mlkem1024_dec
    c_checkPk _ = c_mlkem1024_check_pk
    c_checkSk _ = c_mlkem1024_check_sk

foreign import ccall unsafe "crypton_mlkem512_keypair_derand"
    c_mlkem512_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem512_enc_derand"
    c_mlkem512_enc :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem512_dec"
    c_mlkem512_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem512_check_pk"
    c_mlkem512_check_pk :: Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem512_check_sk"
    c_mlkem512_check_sk :: Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypton_mlkem768_keypair_derand"
    c_mlkem768_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem768_enc_derand"
    c_mlkem768_enc :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem768_dec"
    c_mlkem768_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem768_check_pk"
    c_mlkem768_check_pk :: Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem768_check_sk"
    c_mlkem768_check_sk :: Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypton_mlkem1024_keypair_derand"
    c_mlkem1024_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem1024_enc_derand"
    c_mlkem1024_enc :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem1024_dec"
    c_mlkem1024_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem1024_check_pk"
    c_mlkem1024_check_pk :: Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypton_mlkem1024_check_sk"
    c_mlkem1024_check_sk :: Ptr Word8 -> IO CInt
