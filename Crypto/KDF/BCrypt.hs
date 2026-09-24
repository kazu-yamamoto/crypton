-- | Password encoding and validation using bcrypt.
--
-- Example usage:
--
-- >>> import Crypto.KDF.BCrypt (hashPassword, validatePassword)
-- >>> import qualified Data.ByteString.Char8 as B
-- >>>
-- >>> let bcryptHash = B.pack "$2a$10$MJJifxfaqQmbx1Mhsq3oq.YmMmfNhkyW4s/MS3K5rIMVfB7w0Q/OW"
-- >>> let password = B.pack "password"
-- >>> validatePassword password bcryptHash
-- >>> True
-- >>> let otherPassword = B.pack "otherpassword"
-- >>> otherHash <- hashPassword 12 otherPassword :: IO B.ByteString
-- >>> validatePassword otherPassword otherHash
-- >>> True
--
-- See <https://www.usenix.org/conference/1999-usenix-annual-technical-conference/future-adaptable-password-scheme>
-- for details of the original algorithm.
--
-- The functions @hashPassword@ and @validatePassword@ should be all that
-- most users need.
--
-- Hashes are strings of the form
-- @$2a$10$MJJifxfaqQmbx1Mhsq3oq.YmMmfNhkyW4s/MS3K5rIMVfB7w0Q/OW@ which
-- encode a version number, an integer cost parameter and the concatenated
-- salt and hash bytes (each separately Base64 encoded. Incrementing the
-- cost parameter approximately doubles the time taken to calculate the hash.
--
-- The different version numbers evolved to account for bugs in the standard
-- C implementations. They don't represent different versions of the algorithm
-- itself and in most cases should produce identical results.
-- The most up to date version is @2b@ and this implementation uses the
-- @2b@ version prefix, but will also attempt to validate
-- against hashes with versions @2a@ and @2y@. Version @2@ or @2x@ will be
-- rejected. No attempt is made to differentiate between the different versions
-- when validating a password, but in practice this shouldn't cause any problems
-- if passwords are UTF-8 encoded (which they should be) and less than 256
-- characters long.
--
-- Only the first 72 bytes of a password are used.  The rest is silently
-- ignored, so two passwords sharing a 72-byte prefix produce the same hash and
-- validate against each other.  That is what the original implementation does
-- and is kept for compatibility, but it means a longer
-- passphrase buys nothing past that point, and the limit is on /bytes/ rather
-- than characters -- a UTF-8 passphrase reaches it sooner than its length in
-- characters suggests.  Where passwords may be longer, hash them to a fixed
-- size first, or use "Crypto.KDF.Argon2" or "Crypto.KDF.Scrypt", which have no
-- such limit.
--
-- The cost parameter can be between 4 and 31 inclusive, but anything less than
-- 10 is probably not strong enough. High values may be prohibitively slow
-- depending on your hardware. Choose the highest value you can without having
-- an unacceptable impact on your users. The cost parameter can also be varied
-- depending on the account, since it is unique to an individual hash.
module Crypto.KDF.BCrypt (
    hashPassword,
    tryHashPassword,
    validatePassword,
    validatePasswordEither,
    bcrypt,
    tryBcrypt,
)
where

import Control.Monad (unless, when)
import Crypto.Cipher.Blowfish.Primitive (bcryptHash)
import Crypto.Error
import Crypto.Random (MonadRandom, getRandomBytes)
import Data.ByteArray (
    ByteArray,
    ByteArrayAccess,
    Bytes,
 )
import qualified Data.ByteArray as B
import Data.ByteArray.Encoding
import Data.Char

data BCryptHash = BCH Char Int Bytes Bytes

-- | Create a bcrypt hash for a password with a provided cost value.
-- Typically used to create a hash when a new user account is registered
-- or when a user changes their password.
--
-- Each increment of the cost approximately doubles the time taken.
-- The 16 bytes of random salt will be generated internally.
--
-- A cost outside 4 to 31 raises 'CryptoError_ParameterInvalid';
-- 'tryHashPassword' reports it instead.
hashPassword
    :: (MonadRandom m, ByteArray password, ByteArray hash)
    => Int
    -- ^ The cost parameter. Must be between 4 and 31 inclusive; anything
    -- else is refused.
    -> password
    -- ^ The password. Should be the UTF-8 encoded bytes of the password text.
    -- Only the first 72 bytes are used; see the module documentation.
    -> m hash
    -- ^ The bcrypt hash in standard format.
hashPassword cost password = throwCryptoError <$> tryHashPassword cost password

-- | Create a bcrypt hash for a password with a provided cost value,
-- reporting a cost the implementation refuses rather than raising.
--
-- The salt is generated internally and is always the right length, so the
-- cost is the only thing here that can be wrong.
tryHashPassword
    :: (MonadRandom m, ByteArray password, ByteArray hash)
    => Int
    -- ^ The cost parameter. Must be between 4 and 31 inclusive; anything
    -- else is reported.
    -> password
    -- ^ The password. Should be the UTF-8 encoded bytes of the password text.
    -- Only the first 72 bytes are used; see the module documentation.
    -> m (CryptoFailable hash)
    -- ^ The bcrypt hash in standard format.
tryHashPassword cost password = do
    salt <- getRandomBytes 16
    return $ tryBcrypt cost (salt :: Bytes) password

-- | Create a bcrypt hash for a password with a provided cost value and salt.
--
-- A cost outside 4 to 31, or a salt that is not 16 bytes long, raises
-- 'CryptoError_ParameterInvalid'; 'tryBcrypt' reports the same conditions as
-- 'CryptoFailed'.
bcrypt
    :: (ByteArray salt, ByteArray password, ByteArray output)
    => Int
    -- ^ The cost parameter. Must be between 4 and 31 inclusive; anything
    -- else is refused.
    -> salt
    -- ^ The salt. Must be 16 bytes in length or an error will be raised.
    -> password
    -- ^ The password. Should be the UTF-8 encoded bytes of the password text.
    -- Only the first 72 bytes are used; see the module documentation.
    -> output
    -- ^ The bcrypt hash in standard format.
bcrypt cost salt password = throwCryptoError (tryBcrypt cost salt password)

-- | Create a bcrypt hash for a password with a provided cost value and salt,
-- reporting a parameter the implementation refuses rather than raising.
--
-- bcrypt is defined for a cost of 4 to 31, and a cost outside that is
-- reported rather than replaced by one inside it: a caller that asks for
-- something this does not do should hear so, not receive a hash at a cost it
-- did not choose.
tryBcrypt
    :: (ByteArray salt, ByteArray password, ByteArray output)
    => Int
    -- ^ The cost parameter. Must be between 4 and 31 inclusive; anything
    -- else is refused.
    -> salt
    -- ^ The salt. Must be 16 bytes in length.
    -> password
    -- ^ The password. Should be the UTF-8 encoded bytes of the password text.
    -- Only the first 72 bytes are used; see the module documentation.
    -> CryptoFailable output
    -- ^ The bcrypt hash in standard format.
tryBcrypt cost salt password
    | cost < 4 || cost > 31 = CryptoFailed CryptoError_ParameterInvalid
    | B.length salt /= 16 = CryptoFailed CryptoError_ParameterInvalid
    | otherwise =
        CryptoPassed $
            B.concat [header, B.snoc costBytes dollar, b64 salt, b64 hash]
  where
    hash = rawHash 'b' cost salt password
    header = B.pack [dollar, fromIntegral (ord '2'), fromIntegral (ord 'b'), dollar]
    dollar = fromIntegral (ord '$')
    zero = fromIntegral (ord '0')
    costBytes =
        B.pack
            [ zero + fromIntegral (cost `div` 10)
            , zero + fromIntegral (cost `mod` 10)
            ]

    b64 :: ByteArray ba => ba -> ba
    b64 = convertToBase Base64OpenBSD

-- | Check a password against a stored bcrypt hash when authenticating a user.
--
-- Returns @False@ if the password doesn't match the hash, or if the hash is
-- invalid or an unsupported version.
--
-- Only the first 72 bytes of the password are compared; see the module
-- documentation.
validatePassword
    :: (ByteArray password, ByteArray hash) => password -> hash -> Bool
validatePassword password bcHash = either (const False) id (validatePasswordEither password bcHash)

-- | Check a password against a bcrypt hash
--
-- As for @validatePassword@ but will provide error information if the hash is invalid or
-- an unsupported version.  The same 72-byte limit applies.
validatePasswordEither
    :: (ByteArray password, ByteArray hash) => password -> hash -> Either String Bool
validatePasswordEither password bcHash = do
    BCH version cost salt hash <- parseBCryptHash bcHash
    return $ (rawHash version cost salt password :: Bytes) `B.constEq` hash

rawHash
    :: (ByteArrayAccess salt, ByteArray password, ByteArray output)
    => Char -> Int -> salt -> password -> output
rawHash _ cost salt password = case bcryptHash cost salt key of
    Just hash -> B.take 23 hash -- Another compatibility bug. Ignore last byte of hash
    Nothing -> error "bcrypt: the cost or the salt is not one bcrypt takes"
  where
    -- Truncate the password if necessary and append a null byte for C compatibility
    key = B.snoc (B.take 72 (B.convert password :: Bytes)) 0

-- "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"
parseBCryptHash :: ByteArray ba => ba -> Either String BCryptHash
parseBCryptHash bc = do
    unless
        ( B.length bc == 60
            && B.index bc 0 == dollar
            && B.index bc 1 == fromIntegral (ord '2')
            && B.index bc 3 == dollar
            && B.index bc 6 == dollar
        )
        (Left "Invalid hash format")
    unless
        (version == 'b' || version == 'a' || version == 'y')
        (Left ("Unsupported minor version: " ++ [version]))
    when (costTens > 3 || cost > 31 || cost < 4) (Left "Invalid bcrypt cost")
    (salt, hash) <- decodeSaltHash (B.drop 7 bc)
    return (BCH version cost salt hash)
  where
    dollar = fromIntegral (ord '$')
    zero = ord '0'
    costTens = fromIntegral (B.index bc 4) - zero
    costUnits = fromIntegral (B.index bc 5) - zero
    version = chr (fromIntegral (B.index bc 2))
    cost = costUnits + 10 * costTens :: Int

    decodeSaltHash saltHash = do
        let (s, h) = B.splitAt 22 saltHash
        salt <- convertFromBase Base64OpenBSD s
        hash <- convertFromBase Base64OpenBSD h
        return (salt, hash)
