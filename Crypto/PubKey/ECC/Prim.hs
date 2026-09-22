{-# LANGUAGE BangPatterns #-}

-- | Elliptic Curve Arithmetic.
--
-- /WARNING:/ These functions are vulnerable to timing attacks, except on
-- P-256, whose multiplications go to the C implementation in
-- "Crypto.PubKey.ECC.P256".
module Crypto.PubKey.ECC.Prim (
    scalarGenerate,
    scalarInverse,
    scalarAdd,
    scalarMul,
    pointAdd,
    pointNegate,
    pointDouble,
    pointBaseMul,
    pointMul,
    pointAddTwoMuls,
    pointDecompose,
    pointCompose,
    isPointAtInfinity,
    isPointValid,
) where

import Crypto.Error (maybeCryptoError)
import Crypto.Internal.ECC (CurveField (..), MulResult (..), curveMul)
import Crypto.Number.Basic (numBits, numBytes)
import Crypto.Number.F2m
import Crypto.Number.Generate (generateBetween)
import Crypto.Number.ModArithmetic
import qualified Crypto.PubKey.ECC.P256 as P256
import Crypto.PubKey.ECC.Types
import Crypto.Random
import Data.Bits (shiftL, shiftR, testBit, (.&.))
import Data.Maybe
import Data.Word (Word8)
import Foreign.ForeignPtr (ForeignPtr)

-- | P-256, the one curve here that has a C implementation: 'SEC_p256r1', also
-- known as NIST P-256 and prime256v1.
--
-- A 'Curve' carries its parameters rather than a name, so this compares the
-- parameters.  They are public, so the comparison tells an attacker nothing.
p256Curve :: Curve
p256Curve = getCurveByName SEC_p256r1
{-# NOINLINE p256Curve #-}

p256Order :: Integer
p256Order = ecc_n (common_curve p256Curve)

p256Base :: Point
p256Base = ecc_g (common_curve p256Curve)

-- | A point the C implementation will take: in range, on the curve, and not
-- the point at infinity, which it does not represent.  Anything else is left
-- to the generic code, which answers for points off the curve too.
toP256 :: Point -> Maybe P256.Point
toP256 PointO = Nothing
toP256 (Point x y)
    | x < 0 || y < 0 || x >= limit || y >= limit = Nothing
    | P256.pointIsValid p = Just p
    | otherwise = Nothing
  where
    limit = 1 `shiftL` 256
    p = P256.pointFromIntegers (x, y)

fromP256 :: P256.Point -> Point
fromP256 p
    | P256.pointIsAtInfinity p = PointO
    | otherwise = uncurry Point (P256.pointToIntegers p)

-- | Any 256-bit number as a scalar.
--
-- The arithmetic below takes them as they come: a 256-bit value is barely
-- over the order, and both the multiplication and the addition bring their
-- answer back under it.  'Nothing' is for what does not fit in 256 bits,
-- which no scalar anybody signs with does.
p256Scalar :: Integer -> Maybe P256.Scalar
p256Scalar n
    | n < 0 || n >= 1 `shiftL` 256 = Nothing
    | otherwise = maybeCryptoError (P256.scalarFromInteger n)

-- | The scalar reduced into the range the C implementation takes.
--
-- Every point it accepts has the curve's order, so reducing changes no
-- answer; 'Nothing' means the multiple is the point at infinity, which is the
-- generic code's business.
-- The reduction is a single masked subtraction, so a secret scalar does not
-- steer it, which taking the remainder would: dividing takes a number of
-- steps that follows the number being divided.  Anything wider than 256 bits
-- has to go through a division first, but a scalar that wide is not one
-- anybody signs with.
toP256Scalar :: Integer -> Maybe P256.Scalar
toP256Scalar n = case P256.scalarReduce <$> p256Scalar n of
    Nothing -> toP256Scalar (n `mod` p256Order) -- wider than 256 bits, or below zero
    Just s
        | P256.scalarIsZero s -> Nothing
        | otherwise -> Just s

-- | @n1 * p1 + n2 * p2@ through the C implementation, when one of the points
-- is the base point.  That is the shape signature verification uses.
p256AddTwoMuls :: Integer -> Point -> Integer -> Point -> Maybe Point
p256AddTwoMuls n1 p1 n2 p2
    | p1 == p256Base = withBase n1 n2 p2
    | p2 == p256Base = withBase n2 n1 p1
    | otherwise = Nothing
  where
    withBase a b q =
        fromP256
            <$> (P256.pointsMulVarTime <$> toP256Scalar a <*> toP256Scalar b <*> toP256 q)

-- | Generate a valid scalar for a specific Curve
scalarGenerate :: MonadRandom randomly => Curve -> randomly PrivateNumber
scalarGenerate curve = generateBetween 1 (n - 1)
  where
    n = ecc_n $ common_curve curve

-- | The inverse of a scalar modulo the order of the curve, without letting
-- the scalar steer how long the work takes.  This is what signing needs for
-- its nonce, which is as worth hiding as the private key itself: a handful of
-- signatures whose nonces are partly known give the key away.
--
-- On P-256 the C implementation does it; elsewhere it is 'inverseSafe'.
-- 'Nothing' means the scalar has no inverse, which for the curves in use here
-- means it was a multiple of the order.
scalarInverse :: Curve -> Integer -> Maybe Integer
scalarInverse c k
    | c == p256Curve
    , Just s <- toP256Scalar k =
        Just (P256.scalarToInteger (P256.scalarInvSafe s))
    | otherwise = inverseSafe k (ecc_n $ common_curve c)

-- | Addition modulo the order of the curve.
--
-- On P-256 this is the C implementation's arithmetic, which works in a fixed
-- width and so does not let the values steer it; elsewhere it is 'Integer'
-- arithmetic, whose cost follows the values.
scalarAdd :: Curve -> Integer -> Integer -> Integer
scalarAdd c a b
    | c == p256Curve
    , Just x <- p256Scalar a
    , Just y <- p256Scalar b =
        P256.scalarToInteger (P256.scalarAdd x y)
    | otherwise = (a + b) `mod` ecc_n (common_curve c)

-- | Multiplication modulo the order of the curve, as 'scalarAdd'.
scalarMul :: Curve -> Integer -> Integer -> Integer
scalarMul c a b
    | c == p256Curve
    , Just x <- p256Scalar a
    , Just y <- p256Scalar b =
        P256.scalarToInteger (P256.scalarMul x y)
    | otherwise = (a * b) `mod` ecc_n (common_curve c)

-- TODO: Extract helper function for `fromMaybe PointO...`

-- | Elliptic Curve point negation:
-- @pointNegate c p@ returns point @q@ such that @pointAdd c p q == PointO@.
pointNegate :: Curve -> Point -> Point
pointNegate _ PointO = PointO
pointNegate (CurveFP c) (Point x y) = Point x (ecc_p c - y)
pointNegate CurveF2m{} (Point x y) = Point x (x `addF2m` y)

-- | Elliptic Curve point addition.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAdd :: Curve -> Point -> Point -> Point
pointAdd _ PointO PointO = PointO
pointAdd _ PointO q = q
pointAdd _ p PointO = p
pointAdd c p q
    | p == q = pointDouble c p
    | p == pointNegate c q = PointO
pointAdd (CurveFP (CurvePrime pr _)) (Point xp yp) (Point xq yq) =
    fromMaybe PointO $ do
        s <- divmod (yp - yq) (xp - xq) pr
        let xr = (s ^ (2 :: Int) - xp - xq) `mod` pr
            yr = (s * (xp - xr) - yp) `mod` pr
        return $ Point xr yr
pointAdd (CurveF2m (CurveBinary fx cc)) (Point xp yp) (Point xq yq) =
    fromMaybe PointO $ do
        s <- divF2m fx (yp `addF2m` yq) (xp `addF2m` xq)
        let xr = mulF2m fx s s `addF2m` s `addF2m` xp `addF2m` xq `addF2m` a
            yr = mulF2m fx s (xp `addF2m` xr) `addF2m` xr `addF2m` yp
        return $ Point xr yr
  where
    a = ecc_a cc

-- | Elliptic Curve point doubling.
--
-- /WARNING:/ Vulnerable to timing attacks.
--
-- This perform the following calculation:
-- > lambda = (3 * xp ^ 2 + a) / 2 yp
-- > xr = lambda ^ 2 - 2 xp
-- > yr = lambda (xp - xr) - yp
--
-- With binary curve:
-- > xp == 0   => P = O
-- > otherwise =>
-- >    s = xp + (yp / xp)
-- >    xr = s ^ 2 + s + a
-- >    yr = xp ^ 2 + (s+1) * xr
pointDouble :: Curve -> Point -> Point
pointDouble _ PointO = PointO
pointDouble (CurveFP (CurvePrime pr cc)) (Point xp yp) = fromMaybe PointO $ do
    lambda <- divmod (3 * xp ^ (2 :: Int) + a) (2 * yp) pr
    let xr = (lambda ^ (2 :: Int) - 2 * xp) `mod` pr
        yr = (lambda * (xp - xr) - yp) `mod` pr
    return $ Point xr yr
  where
    a = ecc_a cc
pointDouble (CurveF2m (CurveBinary fx cc)) (Point xp yp)
    | xp == 0 = PointO
    | otherwise = fromMaybe PointO $ do
        s <- return . addF2m xp =<< divF2m fx yp xp
        let xr = mulF2m fx s s `addF2m` s `addF2m` a
            yr = mulF2m fx xp xp `addF2m` mulF2m fx xr (s `addF2m` 1)
        return $ Point xr yr
  where
    a = ecc_a cc

-- | Elliptic curve point multiplication using the base
--
-- On P-256 this reaches the C implementation, which multiplies the base point
-- through a table of its own.
--
-- /WARNING:/ On every other curve, vulnerable to timing attacks.
pointBaseMul :: Curve -> Integer -> Point
pointBaseMul c n = pointMul c n (ecc_g $ common_curve c)

-- | Elliptic curve point multiplication.
--
-- Over a prime field this goes to C, four bits of scalar at a time, with the
-- multiple to add taken from a table read by touching every entry of it.
-- Over a binary field it also goes to C, as Montgomery's ladder: it carries
-- the x coordinates of two consecutive multiples -- their difference being
-- the point is what lets it carry no more than that -- and spends one
-- addition and one doubling on every bit whichever way the bit goes, with the
-- two exchanged by a mask rather than chosen by a branch.  Either way the work
-- follows the width of the curve's order and not the scalar.
--
-- What falls back on the 'Integer' arithmetic below is a point that is not on
-- the curve, the one point of a binary curve that has no x, and a prime the C
-- will not take.
--
-- Multiplying the base point of a curve over a prime field -- which is what
-- signing and making a key do, and nothing else does -- goes through a table
-- of its multiples, built when that curve is first asked for one and kept
-- afterwards.  The build is a few milliseconds and the table a few hundred
-- kilobytes, and a multiplication that uses it takes about a third of what
-- one without it takes.
--
-- On P-256 the multiplication goes to the C implementation in
-- "Crypto.PubKey.ECC.P256", which has a table for the base point.
--
-- /WARNING:/ What is left of the 'Integer' arithmetic below -- a point off
-- the curve, the one point of a binary curve with no x, a prime or a
-- polynomial the C will not take -- has uniform operation counts at best, and
-- uniform operation counts are not constant time: those operations cost what
-- the values they are given cost.
pointMul :: Curve -> Integer -> Point -> Point
pointMul _ _ PointO = PointO
pointMul c n p
    -- the base point has a table of its own in the C, which is what makes key
    -- generation and signing quicker than multiplying any other point
    | c == p256Curve
    , p == p256Base =
        maybe PointO (fromP256 . P256.toPoint) (toP256Scalar n)
    | c == p256Curve
    , Just q <- toP256 p =
        maybe PointO (\s -> fromP256 (P256.pointMul s q)) (toP256Scalar n)
    | n < 0 = pointMul c (-n) (pointNegate c p)
    | n == 0 = PointO
    | otherwise =
        case c of
            CurveFP (CurvePrime pr cc) -> primeMul pr cc
            CurveF2m (CurveBinary fx cc) -> binaryMul fx cc
  where
    -- The C answers for a point on the curve; anything else keeps the
    -- answers it has always had from the code below.  Multiplying the base
    -- point, which is what signing and making a key do, goes through the
    -- table kept for it.
    primeMul pr cc = case p of
        Point px py
            | isPointValid c p ->
                answer slow $
                    curveMul
                        (Prime pr (ecc_a cc) (ecc_b cc))
                        (ecc_n cc)
                        n
                        px
                        py
                        (p == ecc_g cc)
        _ -> slow
      where
        slow =
            jacobianMul
                pr
                (ecc_a cc)
                (max (integerBits n) (integerBits (ecc_n cc)))
                n
                p

    -- The ladder answers for a point on the curve that has an x; the one
    -- point with no x, and anything off the curve, keep what they had.
    binaryMul fx cc = case p of
        Point px py
            | isPointValid c p ->
                answer (affineMul n p) $
                    curveMul (Binary fx (ecc_b cc)) (ecc_n cc) n px py False
        _ -> affineMul n p

    -- what the C could not take goes back to the code that was here before
    answer fallback r = case r of
        MulPoint x y -> Point x y
        MulInfinity -> PointO
        MulUnsupported -> fallback

    affineMul k q
        | k == 0 = PointO
        | k == 1 = q
        | odd k = pointAdd c q (affineMul (k - 1) q)
        | otherwise = affineMul (k `div` 2) (pointDouble c q)

-- | Number of bits needed to write n, for n > 0.
integerBits :: Integer -> Int
integerBits = go 0
  where
    go acc 0 = acc
    go acc k = go (acc + 1) (k `div` 2)

-- | A point in Jacobian coordinates: @(X, Y, Z)@ stands for the affine
-- @(X\/Z^2, Y\/Z^3)@, and @JPointO@ for the point at infinity.
data JPoint = JPointO | JPoint !Integer !Integer !Integer

-- | The field a prime curve works in, and how to reduce into it.
--
-- Most curve primes are @2^k - c@ with @c@ far smaller than the prime.
-- Reducing is then a shift, a multiplication by @c@ and an addition, where
-- dividing a number twice the width costs about four times as much: 227ns
-- against 183 for a P-384 multiplication, and 226 against 89 for P-521, whose
-- @c@ is one.
-- | The prime, the width to fold at, and what to fold back in.  A @c@ of zero
-- says to divide instead, either because the prime has no such shape or
-- because it is too small for folding to pay: @c@ has to be under half the
-- width, or folding would not shrink the number, and below 256 bits the
-- handful of 'Integer' operations folding takes costs more than the division
-- it saves -- measured on P-192, where folding is 14% slower.
data Field = Field !Integer !Int !Integer

mkField :: Integer -> Field
mkField p
    | p > 0 && c > 0 && 2 * numBits c <= k && k >= 256 = Field p k c
    | otherwise = Field p 0 0
  where
    k = numBits p
    c = (1 `shiftL` k) - p

fieldPrime :: Field -> Integer
fieldPrime (Field p _ _) = p

fieldReduce :: Field -> Integer -> Integer
fieldReduce (Field p k c) x
    | c == 0 || x < 0 = x `mod` p
    | otherwise = trim (fold x)
  where
    mask = (1 `shiftL` k) - 1
    fold v
        | v > mask = fold ((v `shiftR` k) * c + (v .&. mask))
        | otherwise = v
    trim v
        | v >= p = trim (v - p)
        | otherwise = v
{-# INLINE fieldReduce #-}

-- | A point in affine coordinates: the second operand of every addition a
-- scalar multiplication makes, where knowing that z is one saves four
-- multiplications of the sixteen.
data Affine = AffineO | Affine !Integer !Integer

jacobianMul :: Integer -> Integer -> Int -> Integer -> Point -> Point
jacobianMul _ _ _ _ PointO = PointO
jacobianMul pr a bits n (Point px py) = fromJacobian f (go (bits - 1) JPointO)
  where
    f = mkField pr
    base = Affine px py

    -- The bangs are what make the addition happen at every bit.  Without
    -- them the one that is not taken stays a thunk and is never worked out,
    -- so the multiplication costs a step for every bit that is set rather
    -- than for every bit there is, and a single measurement tells an attacker
    -- how many bits of the scalar are set.
    go i acc
        | i < 0 = acc
        | otherwise =
            let !d = jDouble f a acc
                !s = jAddAffine f a d base
             in go (i - 1) (if testBit n i then s else d)

jDouble :: Field -> Integer -> JPoint -> JPoint
jDouble _ _ JPointO = JPointO
jDouble f a (JPoint x y z)
    | y == 0 = JPointO
    | otherwise = JPoint x3 y3 z3
  where
    red = fieldReduce f
    yy = red (y * y)
    delta = red (4 * x * yy)
    zz = red (z * z)
    m = red (3 * x * x + a * zz * zz)
    x3 = red (m * m - 2 * delta)
    y3 = red (m * (delta - x3) - 8 * yy * yy)
    z3 = red (2 * y * z)

-- | Add a point whose z is one, which is what a scalar multiplication always
-- adds: u1 is x1, s1 is y1, and z3 is one multiplication rather than two.
jAddAffine :: Field -> Integer -> JPoint -> Affine -> JPoint
jAddAffine _ _ p AffineO = p
jAddAffine _ _ JPointO (Affine x2 y2) = JPoint x2 y2 1
jAddAffine f a p@(JPoint x1 y1 z1) (Affine x2 y2)
    | h /= 0 = JPoint x3 y3 z3
    | r /= 0 = JPointO
    | otherwise = jDouble f a p
  where
    red = fieldReduce f
    z1s = red (z1 * z1)
    u2 = red (x2 * z1s)
    s2 = red (y2 * z1s * z1)
    h = red (u2 - x1)
    r = red (s2 - y1)
    h2 = red (h * h)
    h3 = red (h2 * h)
    x3 = red (r * r - h3 - 2 * x1 * h2)
    y3 = red (r * (x1 * h2 - x3) - y1 * h3)
    z3 = red (h * z1)

fromJacobian :: Field -> JPoint -> Point
fromJacobian _ JPointO = PointO
fromJacobian f (JPoint x y z) =
    case inverse z (fieldPrime f) of
        Nothing -> PointO
        Just zi ->
            let red = fieldReduce f
                zi2 = red (zi * zi)
             in Point (red (x * zi2)) (red (y * zi2 * zi))

-- | Elliptic curve double-scalar multiplication.
--
-- > pointAddTwoMuls c n1 p1 n2 p2 == pointAdd c (pointMul c n1 p1)
-- >                                             (pointMul c n2 p2)
--
-- which, apart from P-256, is how it is done: the two multiplications
-- separately, and then one addition.  P-256 has a double multiplication of
-- its own in C and takes it.
--
-- This used to be Shamir's trick, one pass over the bits of both scalars at
-- once, which shares the doublings between them and is the right thing to do
-- when the two multiplications would cost the same.  They no longer do.
-- 'pointMul' goes to C, and over a prime field it multiplies the base point
-- through a table of its multiples, which is a third of the price of an
-- ordinary multiplication -- and the base point is one of the two here, since
-- signature verification is what asks for this.  Sharing the doublings with a
-- pass in 'Integer' arithmetic gives that up and more: on P-384 it costs
-- twice what two multiplications in C cost, and on the curves over a binary
-- field, whose addition needs an inversion where the C has a ladder that
-- needs none, it costs two hundred times as much.
--
-- Both scalars are public wherever this is called from, so nothing here is
-- meant to hide them.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAddTwoMuls :: Curve -> Integer -> Point -> Integer -> Point -> Point
pointAddTwoMuls c n1 p1 n2 p2
    | c == p256Curve, Just r <- p256AddTwoMuls n1 p1 n2 p2 = r
    | otherwise = pointAdd c (pointMul c n1 p1) (pointMul c n2 p2)

-- | Decompose a point into index, residue, and parity.
--
-- Adapted from SEC 1: Elliptic Curve Cryptography, Version 2.0, section 2.3.3.
pointDecompose :: Curve -> Point -> Maybe (Integer, Integer, Bool)
pointDecompose _ PointO = Nothing
pointDecompose curve (Point x y) = do
    let CurveCommon _ _ _ n _ = common_curve curve
    let (index, residue) = x `divMod` n
    parity <- case curve of
        CurveFP _ -> pure $ odd y
        CurveF2m _ | x == 0 -> pure False
        CurveF2m (CurveBinary fx _) -> odd <$> divF2m fx y x
    pure (index, residue, parity)

-- | Compose a point from index, residue, and parity.
--
-- Adapted from SEC 1: Elliptic Curve Cryptography, Version 2.0, section 2.3.4.
pointCompose :: Curve -> Integer -> Integer -> Bool -> Maybe Point
pointCompose curve index residue parity = do
    let CurveCommon a b _ n _ = common_curve curve
    let x = residue + index * n
    y <- case curve of
        CurveFP (CurvePrime p _) -> do
            z <- squareRoot p $ x ^ (3 :: Int) + a * x + b
            pure $ if odd z == parity then z else p - z
        CurveF2m (CurveBinary fx _) | x == 0 -> pure $ sqrtF2m fx b
        CurveF2m (CurveBinary fx _) -> do
            c <- divF2m fx b $ squareF2m fx x
            z <- quadraticF2m fx $ addF2m x $ addF2m a c
            pure $ mulF2m fx x $ if odd z == parity then z else addF2m 1 z
    pure $ Point x y

-- | Check if a point is the point at infinity.
isPointAtInfinity :: Point -> Bool
isPointAtInfinity PointO = True
isPointAtInfinity _ = False

-- | check if a point is on specific curve
--
-- This perform three checks:
--
-- * x is not out of range
-- * y is not out of range
-- * the equation @y^2 = x^3 + a*x + b (mod p)@ holds
--
-- over a prime curve, and the corresponding checks over a binary curve: the
-- coordinates reduce to themselves in the field, and
-- @y^2 + x*y = x^3 + a*x^2 + b@ holds.
--
-- This is the check to make on a point that arrives from elsewhere, before
-- multiplying it by a private number.  Without it the multiplication is
-- carried out in whatever group the supplied point generates rather than the
-- curve group, and if that group is small the private number can be recovered
-- from the result.
--
-- Two things it does not establish:
--
-- * The point at infinity is reported as valid, since it is a member of the
--   curve group.  It is not a usable peer value: multiplying it by anything
--   yields the point at infinity again, which has no coordinates.  Reject it
--   separately where a peer is not allowed to send it.
--
-- * Being on the curve is not membership of the subgroup generated by the base
--   point.  The two coincide only when the cofactor is 1.  Of the curves in
--   'Crypto.PubKey.ECC.Types.CurveName' that holds for every prime curve
--   except @SEC_p112r2@ and @SEC_p128r2@, whose cofactor is 4, and for no
--   binary curve, whose cofactor is 2 or 4.  Where the cofactor is above 1 a
--   point on the curve may still generate a small subgroup, and ruling that
--   out needs a further check -- multiplying by the group order and requiring
--   the point at infinity, or clearing the cofactor -- that this function does
--   not make.
isPointValid :: Curve -> Point -> Bool
isPointValid _ PointO = True
isPointValid (CurveFP (CurvePrime p cc)) (Point x y) =
    isValid x && isValid y && (y ^ (2 :: Int)) `eqModP` (x ^ (3 :: Int) + a * x + b)
  where
    a = ecc_a cc
    b = ecc_b cc
    eqModP z1 z2 = (z1 `mod` p) == (z2 `mod` p)
    isValid e = e >= 0 && e < p
isPointValid (CurveF2m (CurveBinary fx cc)) (Point x y) =
    and
        [ isValid x
        , isValid y
        , ((((x `add` a) `mul` x `add` y) `mul` x) `add` b `add` (squareF2m fx y)) == 0
        ]
  where
    a = ecc_a cc
    b = ecc_b cc
    add = addF2m
    mul = mulF2m fx
    isValid e = modF2m fx e == e

-- | div and mod
divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod y x m = do
    i <- inverse (x `mod` m) m
    return $ y * i `mod` m
