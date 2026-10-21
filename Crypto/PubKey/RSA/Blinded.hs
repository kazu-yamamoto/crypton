-- |
-- Module      : Crypto.PubKey.RSA.Blinded
-- License     : BSD-style
-- Stability   : experimental
-- Portability : Good
--
-- An RSA private key that keeps its blinding between operations.
--
-- Blinding hides the private-key operation's input from timing: it is
-- multiplied by @r^e@ for a random @r@ first, and the result by @r^-1@
-- after.  Drawing a new @r@ costs a modular inverse and an exponentiation,
-- about a tenth of an RSA-2048 signature.  A t'BlindedKey' draws one and
-- squares the pair for each use after it, which is what OpenSSL does, and
-- draws a new one every 32 uses, from the 'Crypto.Random.Types.MonadRandom'
-- the operation runs in.
--
-- The key is threaded through the operations as a hash context is: each
-- function in "Crypto.PubKey.RSA.PKCS15", "Crypto.PubKey.RSA.PSS" and
-- "Crypto.PubKey.RSA.OAEP" whose name ends in @Blinded@ returns the key for
-- the next one.  The @Safer@ functions there keep a t'BlindedKey' per key
-- themselves, for the last few keys used, so they get the same saving
-- without one being passed.
module Crypto.PubKey.RSA.Blinded (
    BlindedKey,
    blindedKey,
    blindedPrivateKey,
) where

import Crypto.PubKey.RSA.Blinded.Internal
