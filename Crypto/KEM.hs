-- |
-- Module      : Crypto.KEM
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- Key encapsulation: one side publishes a key, the other draws a secret and
-- returns something only the first side can turn back into it.
--
-- The shape is not ML-KEM's alone, which is why this is a class in a module
-- of its own rather than part of any one algorithm: 'Crypto.PubKey.MLKEM'
-- is one instance of it, and a caller that does not care which it has can
-- be written against this.
--
-- A bare Diffie-Hellman exchange is deliberately __not__ an instance, even
-- though the shapes line up.  The KEM a Diffie-Hellman group gives is
-- DHKEM, of RFC 9180 section 4.1, and that is not the raw exchange: its
-- shared secret is the exchange's output run through HKDF with the
-- ephemeral and the recipient public keys as context, under labels that
-- name the ciphersuite.  The binding to those two keys, and the separation
-- between suites, are what the KEM security argument rests on; the raw
-- value has neither.  A protocol can supply the binding at its own level --
-- TLS 1.3 does, in the key schedule -- but then the binding belongs to the
-- protocol, not to this class, and offering the raw exchange here would
-- invite its use somewhere that supplies nothing.  An instance for DHKEM
-- proper can be added when there is one to point at.
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.KEM (
    KEM (..),
    SharedSecret (..),
) where

import Data.Kind (Type)

import Crypto.Error (CryptoFailable)
import Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import Crypto.Internal.Imports
import Crypto.Random (MonadRandom)

-- | Secret shared via key exchange.
newtype SharedSecret = SharedSecret ScrubbedBytes
    deriving (Eq, ByteArrayAccess, NFData)

instance Show SharedSecret where
    show _ = "SharedSecret <redacted>"

instance Semigroup SharedSecret where
    SharedSecret x <> SharedSecret y = SharedSecret (x <> y)

instance Monoid SharedSecret where
    mempty = SharedSecret mempty

-- | A key encapsulation mechanism.
--
-- The three values are named for what they do rather than for what they are
-- in any one algorithm.  In ML-KEM the encapsulation key and the ciphertext
-- are what the names say; in a Diffie-Hellman exchange both are public
-- values of the group, and the \"ciphertext\" is the ephemeral one the
-- encapsulating side generates.  Keeping them apart in the types is what
-- stops one being passed where the other belongs, which they are not
-- interchangeable for even where they have the same representation.
class KEM kem where
    -- | What the encapsulating side is given.
    type EncapsulationKey kem :: Type

    -- | What the decapsulating side keeps.
    type DecapsulationKey kem :: Type

    -- | What travels back, and is decapsulated.
    type Ciphertext kem :: Type

    -- | Generate a key pair for the decapsulating side.
    generateKeyPair
        :: MonadRandom m
        => proxy kem -> m (EncapsulationKey kem, DecapsulationKey kem)

    -- | Draw a secret and encapsulate it against the key.
    --
    -- This can fail, and does for some instances: a Diffie-Hellman exchange
    -- refuses a peer value that would make the secret degenerate, where
    -- ML-KEM has nothing to refuse.
    encapsulate
        :: MonadRandom m
        => proxy kem
        -> EncapsulationKey kem
        -> m (CryptoFailable (Ciphertext kem, SharedSecret))

    -- | Recover the secret.
    decapsulate
        :: proxy kem
        -> DecapsulationKey kem
        -> Ciphertext kem
        -> CryptoFailable SharedSecret
