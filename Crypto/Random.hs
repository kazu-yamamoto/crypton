{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.Random
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
-- Random bytes, drawn either from the system or from a generator whose
-- seed you hold.
--
-- == Drawing from the system
--
-- 'getRandomBytes' in 'IO' is the ordinary way to get bytes nobody can
-- predict.  The length is in bytes and the type is any 'ByteArray', so the
-- result is usually pinned down by where it goes:
--
-- > import Crypto.Random (getRandomBytes)
-- > import Data.ByteString (ByteString)
-- >
-- > nonce <- getRandomBytes 12 :: IO ByteString
--
-- Everything in this library that needs randomness takes it the same way,
-- through a @MonadRandom m =>@ constraint, so running it in 'IO' is the
-- whole of choosing this source:
--
-- > import qualified Crypto.PubKey.RSA as RSA
-- >
-- > (pub, priv) <- RSA.generate 256 0x10001
--
-- Where the operating system offers @getrandom(2)@ or @getentropy(3)@ the
-- bytes come from a ChaCha20 generator belonging to the operating system
-- thread the call runs on, seeded from the system and reseeded as it goes;
-- see "Crypto.Random.SysDRG" for what that is and what it is not.  Where
-- it does not -- Windows, for now -- they come from the system on every
-- call, as they always did.  Either way the caller writes the same line.
--
-- Any Haskell thread may draw, and none has to say which generator it
-- wants:
--
-- > import Control.Concurrent (forkIO)
-- >
-- > mapM_ (\_ -> forkIO (getRandomBytes 32 >>= use)) [1 .. 64 :: Int]
--
-- The generator belongs to the operating system thread that happens to be
-- carrying the Haskell thread when the call is made, and is found through
-- that thread's own storage rather than by anything the caller passes.  A
-- @forkIO@ thread moves between capabilities, so two draws from one Haskell
-- thread may be answered by two generators; they are seeded independently
-- of each other, so it makes no difference which one answers.
--
-- == Drawing from a generator you hold
--
-- A generator of your own is the way to draw many times from one seed.
-- The system is asked once, when the generator is made, and not again.
-- That is how @tls@ does a connection: 'seedNew' when it opens, and
-- everything the handshake needs afterwards from the generator, whose
-- state the connection carries from one draw to the next.
--
-- > import Crypto.Random (ChaChaDRG, drgNewSeed, seedNew, withDRG)
-- >
-- > data Connection = Connection { connRNG :: ChaChaDRG }
-- >
-- > newConnection :: IO Connection
-- > newConnection = do
-- >     seed <- seedNew                   -- the only draw from the system
-- >     return (Connection (drgNewSeed seed))
-- >
-- > -- every later draw advances the connection's own generator
-- > connRandom :: Int -> Connection -> (ByteString, Connection)
-- > connRandom n conn =
-- >     let (bytes, rng') = withDRG (connRNG conn) (getRandomBytes n)
-- >      in (bytes, conn{connRNG = rng'})
--
-- Inside 'withDRG' the same 'getRandomBytes' resolves to the instance for
-- 'MonadPseudoRandom' rather than the one for 'IO', so it touches neither
-- the system nor the per-thread generator: it advances the generator it was
-- given and hands it back.  Keep that generator and the bytes are
-- reproducible from the seed, which is what makes a test repeatable -- and
-- what makes a generator unfit for keys unless its seed came from the
-- system.
--
-- 'drgNew' is 'seedNew' and 'drgNewSeed' in one step; 'drgNewTest' takes
-- four numbers instead of a seed, for a test that must give the same answer
-- twice.
--
-- == Drawing from a monad stacked on IO
--
-- There are two instances, one for 'IO' and one for 'MonadPseudoRandom',
-- and none for the transformers, so a @ReaderT env IO@ or a @StateT s IO@
-- reaches the system through 'liftIO':
--
-- > import Control.Monad.IO.Class (liftIO)
-- > import Control.Monad.Trans.Reader (ReaderT)
-- >
-- > newKey :: ReaderT env IO ByteString
-- > newKey = liftIO (getRandomBytes 32)
--
-- What that draws is what the first section describes, no more and no less:
-- the 'IO' instance, the generator of the operating system thread the call
-- lands on, seeded from the system and reseeded as it goes.  'liftIO' says
-- which monad the draw happens in and nothing about where the bytes come
-- from.
--
-- Writing an instance for the stack instead would make the choice invisible
-- at the call site, and the class cannot tell a strong source from a weak
-- one -- see 'MonadRandom'.
--
-- == When the system will not give any
--
-- Drawing randomness is the one thing here with nothing to fall back on,
-- so the failure is an exception rather than a value: there is no sensible
-- 'Maybe' to return and no partial answer worth having.  Since 2.2 it is an
-- 'EntropyError' and not a @Control.Exception.ErrorCall@ or an
-- @Control.Exception.IOException@, which is worth knowing if you were
-- catching one of those:
--
-- > import Control.Exception (catch)
-- > import Crypto.Random (EntropyError (..), getRandomBytes)
-- >
-- > key <- getRandomBytes 32 `catch` \e -> case e of
-- >     NoEntropySource   -> fail "this system offers no randomness at all"
-- >     EntropyShort w g  -> fail (show w ++ " bytes wanted, " ++ show g ++ " arrived")
-- >     EntropySourceLost s -> fail ("the source " ++ s ++ " went away")
--
-- Catching it at all is a decision rather than a default.  A program that
-- cannot get randomness cannot make a key, and stopping is usually the
-- honest thing; the reason to catch is to say so in the program's own
-- terms rather than in crypton's.
module Crypto.Random (
    -- * Drawing from the system
    MonadRandom (..),

    -- * Drawing from a generator you hold
    Seed,
    seedNew,
    seedFromInteger,
    seedToInteger,
    seedFromBinary,
    drgNewSeed,
    drgNew,
    drgNewTest,
    withDRG,
    withRandomBytes,
    MonadPseudoRandom,
    DRG (..),

    -- * The generators
    ChaChaDRG,
    SystemDRG,
    getSystemDRG,

    -- * When the system will not give any
    EntropyError (..),
) where

import Crypto.Error
import Crypto.Internal.Imports
import Crypto.Random.ChaChaDRG
import Crypto.Random.Entropy (EntropyError (..))
import Crypto.Random.SystemDRG
import Crypto.Random.Types
import Data.ByteArray (ByteArray, ByteArrayAccess, ScrubbedBytes)
import qualified Data.ByteArray as B

import qualified Crypto.Number.Serialize as Serialize

#ifdef INSECURE_ENTROPY
import Crypto.Hash (SHA512, Context)
import Crypto.Hash.IO
import Data.Memory.PtrMethods (memSet)
import Foreign.Ptr (Ptr, castPtr)
#endif

-- | The material a deterministic generator is built from.  Two generators
-- made from one seed produce the same bytes, which is what 'drgNewSeed' is
-- for and why a seed kept anywhere is as good as the keys drawn from it.
newtype Seed = Seed ScrubbedBytes
    deriving (ByteArrayAccess)

-- Length for ChaCha DRG seed
seedLength :: Int
seedLength = 40

-- | Create a new Seed from system entropy
seedNew :: MonadRandom randomly => randomly Seed

#ifdef INSECURE_ENTROPY
-- The degree of its randomness depends on the source, e.g. for iOS we
-- have to compile with DoNotUseEntropy flag, as iOS doesn't allow
-- using getentropy, and on some other systems it can be also
-- potentially comprisable sources. Hashing of entropy before using
-- it as a seed is a common mitigation for attacks via RNG/entropy
-- source.
seedNew = (Seed . scrubbedHash512) `fmap` getRandomBytes 64

scrubbedHash512 :: ScrubbedBytes -> ScrubbedBytes
scrubbedHash512 = B.take seedLength . hash512
  where
    hash512 ba = B.unsafeCreate (hashDigestSize (undefined :: SHA512)) $ hashIO ba
    hashIO ba ptr = do
        ctx <- hashMutableInit
        hashMutableUpdate (ctx :: MutableContext SHA512) ba
        B.withByteArray ctx $ \pctx -> do
            hashInternalFinalize (castPtr pctx :: Ptr (Context SHA512)) ptr
            memSet pctx 0 $ hashInternalContextSize (undefined :: SHA512)
#else
seedNew = Seed `fmap` getRandomBytes seedLength
#endif

-- | Convert a Seed to an integer
seedToInteger :: Seed -> Integer
seedToInteger (Seed b) = Serialize.os2ip b

-- | Convert an integer to a Seed
seedFromInteger :: Integer -> Seed
seedFromInteger i = Seed $ Serialize.i2ospOf_ seedLength (i `mod` 2 ^ (seedLength * 8))

-- | Convert a binary to a seed
seedFromBinary :: ByteArrayAccess b => b -> CryptoFailable Seed
seedFromBinary b
    | B.length b /= 40 = CryptoFailed (CryptoError_SeedSizeInvalid)
    | otherwise = CryptoPassed $ Seed $ B.convert b

-- | Create a new DRG from system entropy
drgNew :: MonadRandom randomly => randomly ChaChaDRG
drgNew = drgNewSeed `fmap` seedNew

-- | Create a new DRG from a seed
drgNewSeed :: Seed -> ChaChaDRG
drgNewSeed (Seed seed) = initialize seed

-- | Create a new DRG from 5 Word64.
--
-- This is a convenient interface to create deterministic interface
-- for quickcheck style testing.
--
-- It can also be used in other contexts provided the input
-- has been properly randomly generated.
--
-- Note that the @Arbitrary@ instance provided by QuickCheck for 'Word64' does
-- not have a uniform distribution.  It is often better to use instead
-- @arbitraryBoundedRandom@.
--
-- System endianness impacts how the tuple is interpreted and therefore changes
-- the resulting DRG.
drgNewTest :: (Word64, Word64, Word64, Word64, Word64) -> ChaChaDRG
drgNewTest = initializeWords

-- | Generate @len random bytes and mapped the bytes to the function @f.
--
-- This is equivalent to use Control.Arrow 'first' with 'randomBytesGenerate'
withRandomBytes :: (ByteArray ba, DRG g) => g -> Int -> (ba -> a) -> (a, g)
withRandomBytes rng len f = (f bs, rng')
  where
    (bs, rng') = randomBytesGenerate len rng
