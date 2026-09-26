{-# LANGUAGE BangPatterns #-}

-- |
-- Module      : Crypto.Number.ModArithmetic
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- Modular arithmetic on 'Integer'.
--
-- == What an 'Integer' shows
--
-- An 'Integer' is as long as its value needs, and every operation on one
-- costs what that length says.  A secret that happens to be short is
-- multiplied, reduced and compared in fewer words than a full-length one, and
-- the difference is there to be measured.  'expSafe' and 'inverseSafe' keep
-- the /value/ of an exponent or of a number being inverted out of the work
-- they do, and that is as far as an 'Integer' can be taken: hiding the length
-- as well means a fixed-width representation, which is what the curve modules
-- and 'expSafe' itself use underneath.
module Crypto.Number.ModArithmetic (
    -- * Exceptions
    CoprimesAssertionError (..),
    ModulusAssertionError (..),

    -- * Exponentiation
    expSafe,
    expFast,

    -- * Inverse computing
    inverse,
    inverseSafe,
    inverseCoprimes,
    inverseFermat,

    -- * Squares
    jacobi,
    squareRoot,
) where

import qualified Control.Exception as E
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Number.Basic
import Crypto.Number.Compat
import qualified Crypto.Number.Serialize.Internal as Internal
import Data.Memory.PtrMethods (memSet)
import Data.Word (Word32, Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, plusPtr)

-- | Raised when two numbers are supposed to be coprimes but are not.
data CoprimesAssertionError = CoprimesAssertionError
    deriving (Show)

instance E.Exception CoprimesAssertionError

-- | Compute the modular exponentiation of base^exponent using
-- algorithms design to avoid side channels and timing measurement
--
-- Modulo need to be odd otherwise the normal fast modular exponentiation
-- is used.
--
-- With an odd modulo the work is done in C, four bits of exponent at a time:
-- four squarings and one multiplication by a small power of the base, taken
-- from a table of sixteen which is read by touching every entry and keeping
-- one of them with a mask.  So each group of four bits costs the same five
-- multiplications and the same sixteen reads whatever those bits are, and
-- nothing branches on the exponent or indexes memory with it.
--
-- What the exponent still shows is its length: it is rounded up to a whole
-- 64-bit word and every bit of that is walked over, so its value is hidden
-- but its size is not.  The @mpz_powm_sec@ of GMP, which GHC stopped
-- offering in integer-gmp 1.1 and which this replaces, hides exactly as much.
--
-- The base is taken to be public -- in this library it is a ciphertext, a
-- public value from a peer, or a generator -- and is reduced modulo the
-- modulus in the ordinary way first.
--
-- Hiding the exponent has a price: against the windowed exponentiation of
-- GMP, which is what this function used to end up calling, a 2048-bit
-- modulus costs somewhat over twice as much.
expSafe
    :: Integer
    -- ^ base
    -> Integer
    -- ^ exponent
    -> Integer
    -- ^ modulo
    -> Integer
    -- ^ result
expSafe b e m
    | odd m && m > 1 && e >= 0 =
        gmpPowModSecInteger b e m `onGmpUnsupported` expSec (b `mod` m) e m
    -- a modulus of one, and a negative exponent asking for an inverse, are
    -- left to the path they have always taken
    | otherwise =
        gmpPowModInteger b e m
            `onGmpUnsupported` exponentiation b e m

-- | The windowed exponentiation itself, in C.  The base has to be reduced
-- already, the exponent to be zero or more, and the modulus odd and above
-- one.
expSec :: Integer -> Integer -> Integer -> Integer
expSec b e m = unsafeDoIO $
    allocaBytes (sum widths) $ \start -> case scanl plusPtr start widths of
        (out : base : expo : modu : _) -> do
            _ <- Internal.i2ospOf b base mLen
            _ <- Internal.i2ospOf e expo eLen
            _ <- Internal.i2ospOf m modu mLen
            r <-
                c_powm_sec
                    out
                    base
                    (fromIntegral mLen)
                    expo
                    (fromIntegral eLen)
                    modu
                    (fromIntegral mLen)
            -- the exponent is the caller's secret, and this is the last place it
            -- is written out in the clear
            memSet expo 0 eLen
            if r == 0
                then do
                    !v <- Internal.os2ip out mLen
                    return v
                else
                    return
                        ( gmpPowModInteger b e m
                            `onGmpUnsupported` exponentiation b e m
                        )
        _ -> return 0 -- there are four, but say so anyway
  where
    !mLen = numBytes m
    -- the answer, the base, the exponent and the modulus.  The room to take
    -- and where each one starts both come from here, so they cannot drift
    -- apart.
    widths = [mLen, mLen, eLen, mLen]
    -- whole words of exponent, so that the count of them says as little as
    -- what GMP's own secure exponentiation lets slip
    !eLen = 8 * ((numBytes e + 7) `div` 8)

foreign import ccall safe "crypton_powm_sec"
    c_powm_sec
        :: Ptr Word8
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Word32
        -> Ptr Word8
        -> Word32
        -> IO CInt

-- | Compute the modular exponentiation of base^exponent using
-- the fastest algorithm without any consideration for
-- hiding parameters.
--
-- Use this function when all the parameters are public,
-- otherwise 'expSafe' should be preferred.
expFast
    :: Integer
    -- ^ base
    -> Integer
    -- ^ exponent
    -> Integer
    -- ^ modulo
    -> Integer
    -- ^ result
expFast b e m = gmpPowModInteger b e m `onGmpUnsupported` exponentiation b e m

-- | @exponentiation@ computes modular exponentiation as /b^e mod m/
-- using repetitive squaring.
exponentiation :: Integer -> Integer -> Integer -> Integer
exponentiation b e m
    | b == 1 = b
    | e == 0 = 1
    | e == 1 = b `mod` m
    | even e =
        let p = exponentiation b (e `div` 2) m `mod` m
         in (p ^ (2 :: Integer)) `mod` m
    | otherwise = (b * exponentiation b (e - 1) m) `mod` m

-- | @inverse@ computes the modular inverse as in /g^(-1) mod m/.
inverse :: Integer -> Integer -> Maybe Integer
inverse g m = gmpInverse g m `onGmpUnsupported` v
  where
    v
        | d > 1 = Nothing
        | otherwise = Just (x `mod` m)
    (x, _, d) = gcde g m

-- | Compute the modular inverse of two coprime numbers.
-- This is equivalent to inverse except that the result
-- is known to exists.
--
-- If the numbers are not defined as coprime, this function
-- will raise a t'CoprimesAssertionError'.
inverseCoprimes :: Integer -> Integer -> Integer
inverseCoprimes g m =
    case inverse g m of
        Nothing -> E.throw CoprimesAssertionError
        Just i -> i

-- | Computes the Jacobi symbol (a/n).
-- 0 ≤ a < n; n ≥ 3 and odd.
--
-- The Legendre and Jacobi symbols are indistinguishable exactly when the
-- lower argument is an odd prime, in which case they have the same value.
--
-- See algorithm 2.149 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
jacobi :: Integer -> Integer -> Maybe Integer
jacobi a n
    | n < 3 || even n = Nothing
    | a == 0 || a == 1 = Just a
    | n <= a = jacobi (a `mod` n) n
    | a < 0 =
        let b = if n `mod` 4 == 1 then 1 else -1
         in fmap (* b) (jacobi (-a) n)
    | otherwise =
        let (e, a1) = asPowerOf2AndOdd a
            nMod8 = n `mod` 8
            nMod4 = n `mod` 4
            a1Mod4 = a1 `mod` 4
            s' = if even e || nMod8 == 1 || nMod8 == 7 then 1 else -1
            s = if nMod4 == 3 && a1Mod4 == 3 then -s' else s'
            n1 = n `mod` a1
         in if a1 == 1
                then Just s
                else fmap (* s) (jacobi n1 a1)

-- | Modular inverse using Fermat's little theorem.  This works only when
-- the modulus is prime but avoids side channels like in 'expSafe'.
inverseFermat :: Integer -> Integer -> Integer
inverseFermat g p = expSafe g (p - 2) p

-- | @inverseSafe@ computes the modular inverse without letting the number
-- being inverted steer how long the work takes, which is what 'inverse' does:
-- the extended Euclidean algorithm takes a number of steps that follows the
-- bits it is given, and a nonce inverted that way has been taken apart before
-- by watching the steps go by.
--
-- The answer comes from a fixed number of division steps where the assembly
-- for them is built, and from 'inverseFermat' where it is not.  Either way it
-- is checked here by multiplying out: neither one says when the number has no
-- inverse -- the first returns something that is not one and the second
-- returns something that is not one either -- so the check is what makes this
-- agree with 'inverse' on every input, and 'inverse' is asked when it fails.
-- That fallback is reached only by parameters that are already broken.
--
-- The division steps cost about a twentieth of the exponentiation: on an
-- Apple M4, inverting modulo the P-256 group order is 0.80 microseconds
-- against 6.02, and modulo the P-521 one 2.05 against 63.2.
inverseSafe :: Integer -> Integer -> Maybe Integer
inverseSafe g m
    | m > 1 && (g * r) `mod` m == 1 = Just r
    | otherwise = inverse g m
  where
    r = case inverseSec g m of
        Just v -> v
        Nothing -> inverseFermat g m

-- | The inverse in a fixed number of division steps, from the vendored
-- assembly.  'Nothing' when that is not built, when the modulus is even --
-- where the routine answers without saying it cannot -- or when the numbers
-- are larger than it keeps room for.  The answer is not checked here; the
-- caller does that.
inverseSec :: Integer -> Integer -> Maybe Integer
inverseSec g m
    | m <= 1 || even m || g < 0 = Nothing
    | otherwise = unsafeDoIO $
        allocaBytes (3 * mLen) $ \out -> do
            let gp = out `plusPtr` mLen
                mp = gp `plusPtr` mLen
            _ <- Internal.i2ospOf (g `mod` m) gp mLen
            _ <- Internal.i2ospOf m mp mLen
            r <- c_modinv_sec out gp mp (fromIntegral mLen)
            if r == 0
                then do
                    !v <- Internal.os2ip out mLen
                    return (Just v)
                else return Nothing
  where
    !mLen = numBytes m

foreign import ccall unsafe "crypton_modinv_sec"
    c_modinv_sec
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Word32
        -> IO CInt

-- | Raised when the assumption about the modulus is invalid.
data ModulusAssertionError = ModulusAssertionError
    deriving (Show)

instance E.Exception ModulusAssertionError

-- | Modular square root of @g@ modulo a prime @p@.
--
-- If the modulus is found not to be prime, the function will raise a
-- t'ModulusAssertionError'.
--
-- This implementation is variable time and should be used with public
-- parameters only.
squareRoot :: Integer -> Integer -> Maybe Integer
squareRoot p
    | p < 2 = E.throw ModulusAssertionError
    | otherwise =
        case p `divMod` 8 of
            (v, 3) -> method1 (2 * v + 1)
            (v, 7) -> method1 (2 * v + 2)
            (u, 5) -> method2 u
            (_, 1) -> tonelliShanks p
            (0, 2) -> \a -> Just (if even a then 0 else 1)
            _ -> E.throw ModulusAssertionError
  where
    x `eqMod` y = (x - y) `mod` p == 0

    validate g y
        | (y * y) `eqMod` g = Just y
        | otherwise = Nothing

    -- p == 4u + 3 and u' == u + 1
    method1 u' g =
        let y = expFast g u' p
         in validate g y

    -- p == 8u + 5
    method2 u g =
        let gamma = expFast (2 * g) u p
            g_gamma = g * gamma
            i = (2 * g_gamma * gamma) `mod` p
            y = (g_gamma * (i - 1)) `mod` p
         in validate g y

tonelliShanks :: Integer -> Integer -> Maybe Integer
tonelliShanks p a
    | aa == 0 = Just 0
    | otherwise =
        case expFast aa p2 p of
            b
                | b == p1 -> Nothing
                | b == 1 ->
                    Just $
                        go
                            (expFast aa ((s + 1) `div` 2) p)
                            (expFast aa s p)
                            (expFast n s p)
                            e
                | otherwise -> E.throw ModulusAssertionError
  where
    aa = a `mod` p
    p1 = p - 1
    p2 = p1 `div` 2
    n = findN 2

    x `mul` y = (x * y) `mod` p

    pow2m 0 x = x
    pow2m i x = pow2m (i - 1) (x `mul` x)

    (e, s) = asPowerOf2AndOdd p1

    -- find a quadratic non-residue
    findN i
        | expFast i p2 p == p1 = i
        | otherwise = findN (i + 1)

    -- find m such that b^(2^m) == 1 (mod p)
    findM b i
        | b == 1 = i
        | otherwise = findM (b `mul` b) (i + 1)

    go !x b g !r
        | b == 1 = x
        | otherwise =
            let r' = findM b 0
                z = pow2m (r - r' - 1) g
                x' = x `mul` z
                b' = b `mul` g'
                g' = z `mul` z
             in go x' b' g' r'
