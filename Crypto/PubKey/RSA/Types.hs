{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.PubKey.RSA.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.PubKey.RSA.Types (
    Error (..),
    Blinder (..),
    PublicKey (..),
    PrivateKey (..),
    KeyPair (..),
    toPublicKey,
    toPrivateKey,
    private_size,
    private_n,
    private_e,
) where

import Crypto.Debug (DebugShow (..))
import Crypto.Internal.Imports
import Data.Data

import GHC.Generics

-- | Blinder which is used to obfuscate the timing
-- of the decryption primitive (used by decryption and signing).
data Blinder = Blinder !Integer !Integer
    deriving (Show, Eq)

-- | error possible during encryption, decryption or signing.
data Error
    = -- | the message to decrypt is not of the correct size (need to be == private_size)
      MessageSizeIncorrect
    | -- | the message to encrypt is too long
      MessageTooLong
    | -- | the message decrypted doesn't have a PKCS15 structure (0 2 .. 0 msg)
      MessageNotRecognized
    | -- | the message's digest is too long
      SignatureTooLong
    | -- | some parameters lead to breaking assumptions.
      InvalidParameters
    deriving (Show, Eq)

-- | Represent a RSA public key
data PublicKey = PublicKey
    { public_size :: Int
    -- ^ size of key in bytes
    , public_n :: Integer
    -- ^ public p*q
    , public_e :: Integer
    -- ^ public exponent e
    }
    deriving (Show, Read, Eq, Data, Generic)

instance NFData PublicKey where
    rnf (PublicKey sz n e) = rnf n `seq` rnf e `seq` sz `seq` ()

-- | Represent a RSA private key.
--
-- Only the pub, d fields are mandatory to fill.
--
-- p, q, dP, dQ, qinv are by-product during RSA generation,
-- but are useful to record here to speed up massively
-- the decrypt and sign operation.
--
-- implementations can leave optional fields to 0.
data PrivateKey = PrivateKey
    { private_pub :: PublicKey
    -- ^ public part of a private key (size, n and e)
    , private_d :: Integer
    -- ^ private exponent d
    , private_p :: Integer
    -- ^ p prime number
    , private_q :: Integer
    -- ^ q prime number
    , private_dP :: Integer
    -- ^ d mod (p-1)
    , private_dQ :: Integer
    -- ^ d mod (q-1)
    , private_qinv :: Integer
    -- ^ q^(-1) mod p
    }
    deriving (Read, Eq, Data, Generic)

-- | The public part is shown; the secret fields are not.  Use
-- 'Crypto.Debug.debugShow' to see them.
instance Show PrivateKey where
    showsPrec d k =
        showParen (d > 10) $
            showString "PrivateKey {private_pub = "
                . shows (private_pub k)
                . showString
                    ", private_d = <secret>, private_p = <secret>\
                    \, private_q = <secret>, private_dP = <secret>\
                    \, private_dQ = <secret>, private_qinv = <secret>}"

instance DebugShow PrivateKey where
    debugShow k =
        showString "PrivateKey {private_pub = "
            . shows (private_pub k)
            . showString ", private_d = "
            . shows (private_d k)
            . showString ", private_p = "
            . shows (private_p k)
            . showString ", private_q = "
            . shows (private_q k)
            . showString ", private_dP = "
            . shows (private_dP k)
            . showString ", private_dQ = "
            . shows (private_dQ k)
            . showString ", private_qinv = "
            . shows (private_qinv k)
            . showChar '}'
            $ ""

instance NFData PrivateKey where
    rnf (PrivateKey pub d p q dp dq qinv) =
        rnf pub `seq`
            rnf d `seq`
                rnf p `seq`
                    rnf q `seq`
                        rnf dp `seq`
                            rnf dq `seq`
                                qinv `seq`
                                    ()

-- | get the size in bytes from a private key
private_size :: PrivateKey -> Int
private_size = public_size . private_pub

-- | get n from a private key
private_n :: PrivateKey -> Integer
private_n = public_n . private_pub

-- | get e from a private key
private_e :: PrivateKey -> Integer
private_e = public_e . private_pub

-- | Represent RSA KeyPair
--
-- note the RSA private key contains already an instance of public key for efficiency
newtype KeyPair = KeyPair PrivateKey
    deriving (Read, Eq, Data, NFData)

instance Show KeyPair where
    showsPrec d (KeyPair k) =
        showParen (d > 10) $ showString "KeyPair " . showsPrec 11 k

instance DebugShow KeyPair where
    debugShow (KeyPair k) = "KeyPair (" ++ debugShow k ++ ")"

-- | Public key of a RSA KeyPair
toPublicKey :: KeyPair -> PublicKey
toPublicKey (KeyPair priv) = private_pub priv

-- | Private key of a RSA KeyPair
toPrivateKey :: KeyPair -> PrivateKey
toPrivateKey (KeyPair priv) = priv
