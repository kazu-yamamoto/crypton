{-# LANGUAGE ScopedTypeVariables #-}

-- | Elliptic Curve Arithmetic.
--
-- /WARNING:/ These functions are vulnerable to timing attacks.
module Crypto.ECC.Simple.Prim (
    scalarGenerate,
    scalarFromInteger,
    pointAdd,
    pointNegate,
    pointDouble,
    pointBaseMul,
    pointMul,
    pointAddTwoMuls,
    pointFromIntegers,
    isPointAtInfinity,
    isPointValid,
) where

import Crypto.ECC.Simple.Types
import Crypto.Error
import Crypto.Number.F2m
import Crypto.Number.Generate (generateBetween)
import Crypto.Number.ModArithmetic
import Crypto.Random
import Data.Bits (testBit)
import Data.Maybe
import Data.Proxy

-- | Generate a valid scalar for a specific Curve
scalarGenerate
    :: forall randomly curve
     . (MonadRandom randomly, Curve curve) => randomly (Scalar curve)
scalarGenerate =
    Scalar <$> generateBetween 1 (n - 1)
  where
    n = curveEccN $ curveParameters (Proxy :: Proxy curve)

scalarFromInteger
    :: forall curve. Curve curve => Integer -> CryptoFailable (Scalar curve)
scalarFromInteger n
    | n < 0 || n >= mx = CryptoFailed $ CryptoError_EcScalarOutOfBounds
    | otherwise = CryptoPassed $ Scalar n
  where
    mx = case curveType (Proxy :: Proxy curve) of
        CurveBinary (CurveBinaryParam b) -> b
        CurvePrime (CurvePrimeParam p) -> p

-- TODO: Extract helper function for `fromMaybe PointO...`

-- | Elliptic Curve point negation:
-- @pointNegate p@ returns point @q@ such that @pointAdd p q == PointO@.
pointNegate :: Curve curve => Point curve -> Point curve
pointNegate PointO = PointO
pointNegate point@(Point x y) =
    case curveType point of
        CurvePrime (CurvePrimeParam p) -> Point x (p - y)
        CurveBinary{} -> Point x (x `addF2m` y)

-- | Elliptic Curve point addition.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAdd :: Curve curve => Point curve -> Point curve -> Point curve
pointAdd PointO PointO = PointO
pointAdd PointO q = q
pointAdd p PointO = p
pointAdd p q
    | p == q = pointDouble p
    | p == pointNegate q = PointO
pointAdd point@(Point xp yp) (Point xq yq) =
    case ty of
        CurvePrime (CurvePrimeParam pr) -> fromMaybe PointO $ do
            s <- divmod (yp - yq) (xp - xq) pr
            let xr = (s ^ (2 :: Int) - xp - xq) `mod` pr
                yr = (s * (xp - xr) - yp) `mod` pr
            return $ Point xr yr
        CurveBinary (CurveBinaryParam fx) -> fromMaybe PointO $ do
            s <- divF2m fx (yp `addF2m` yq) (xp `addF2m` xq)
            let xr = mulF2m fx s s `addF2m` s `addF2m` xp `addF2m` xq `addF2m` a
                yr = mulF2m fx s (xp `addF2m` xr) `addF2m` xr `addF2m` yp
            return $ Point xr yr
  where
    ty = curveType point
    cc = curveParameters point
    a = curveEccA cc

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
pointDouble :: Curve curve => Point curve -> Point curve
pointDouble PointO = PointO
pointDouble point@(Point xp yp) =
    case ty of
        CurvePrime (CurvePrimeParam pr) -> fromMaybe PointO $ do
            lambda <- divmod (3 * xp ^ (2 :: Int) + a) (2 * yp) pr
            let xr = (lambda ^ (2 :: Int) - 2 * xp) `mod` pr
                yr = (lambda * (xp - xr) - yp) `mod` pr
            return $ Point xr yr
        CurveBinary (CurveBinaryParam fx)
            | xp == 0 -> PointO
            | otherwise -> fromMaybe PointO $ do
                s <- return . addF2m xp =<< divF2m fx yp xp
                let xr = mulF2m fx s s `addF2m` s `addF2m` a
                    yr = mulF2m fx xp xp `addF2m` mulF2m fx xr (s `addF2m` 1)
                return $ Point xr yr
  where
    ty = curveType point
    cc = curveParameters point
    a = curveEccA cc

-- | Elliptic curve point multiplication using the base
--
-- /WARNING:/ Vulnerable to timing attacks.
pointBaseMul :: Curve curve => Scalar curve -> Point curve
pointBaseMul n = pointMul n (curveEccG $ curveParameters (Proxy :: Proxy curve))

-- | Elliptic curve point multiplication.
--
-- Over a prime field this works in Jacobian coordinates, so that the
-- division each addition and doubling would otherwise need is deferred to a
-- single one at the end, and it adds at every bit whether or not the bit is
-- set, so the number of operations depends on the size of the curve's order
-- rather than on the scalar.  Binary curves keep the affine double-and-add.
--
-- /WARNING:/ Still vulnerable to timing attacks.  Uniform operation counts
-- are not constant time: the operations are 'Integer' arithmetic, whose cost
-- depends on the values, and the choice at each bit is a branch.  See the
-- note in "Crypto.ECC".
pointMul
    :: forall curve. Curve curve => Scalar curve -> Point curve -> Point curve
pointMul _ PointO = PointO
pointMul (Scalar n) p
    | n == 0 = PointO
    | n < 0 = pointNegate (pointMul (Scalar (negate n) :: Scalar curve) p)
    | otherwise =
        case curveType (Proxy :: Proxy curve) of
            CurvePrime (CurvePrimeParam pr) -> jacobianMul pr a bits n p
            CurveBinary _ -> affineMul n p
  where
    cc = curveParameters (Proxy :: Proxy curve)
    a = curveEccA cc
    -- Count to the width of the order, which is public, so a scalar in
    -- range -- which is every secret one -- takes the same number of steps
    -- whatever it is.  A scalar may still be given out of range, and then
    -- the count has to follow it or the high bits would be dropped.
    bits = max (integerBits n) (integerBits (curveEccN cc))

    affineMul k q
        | k == 0 = PointO
        | k == 1 = q
        | odd k = pointAdd q (affineMul (k - 1) q)
        | otherwise = affineMul (k `div` 2) (pointDouble q)

-- | Number of bits needed to write n, for n > 0.
integerBits :: Integer -> Int
integerBits = go 0
  where
    go acc 0 = acc
    go acc k = go (acc + 1) (k `div` 2)

-- | A point in Jacobian coordinates: @(X, Y, Z)@ stands for the affine
-- @(X\/Z^2, Y\/Z^3)@, and @JPointO@ for the point at infinity.  Only ever
-- used inside this module, since 'Point' is what the curve exposes.
data JPoint = JPointO | JPoint !Integer !Integer !Integer

jacobianMul
    :: Integer -> Integer -> Int -> Integer -> Point curve -> Point curve
jacobianMul _ _ _ _ PointO = PointO
jacobianMul pr a bits n (Point px py) = fromJacobian pr (go (bits - 1) JPointO)
  where
    base = JPoint px py 1

    go i acc
        | i < 0 = acc
        | otherwise =
            let d = jDouble pr a acc
                s = jAdd pr a d base
             in go (i - 1) (if testBit n i then s else d)

jDouble :: Integer -> Integer -> JPoint -> JPoint
jDouble _ _ JPointO = JPointO
jDouble pr a (JPoint x y z)
    | y == 0 = JPointO
    | otherwise = JPoint x3 y3 z3
  where
    yy = (y * y) `mod` pr
    delta = (4 * x * yy) `mod` pr
    zz = (z * z) `mod` pr
    m = (3 * x * x + a * zz * zz) `mod` pr
    x3 = (m * m - 2 * delta) `mod` pr
    y3 = (m * (delta - x3) - 8 * yy * yy) `mod` pr
    z3 = (2 * y * z) `mod` pr

jAdd :: Integer -> Integer -> JPoint -> JPoint -> JPoint
jAdd _ _ JPointO q = q
jAdd _ _ p JPointO = p
jAdd pr a p@(JPoint x1 y1 z1) (JPoint x2 y2 z2)
    | h /= 0 = JPoint x3 y3 z3
    | r /= 0 = JPointO
    | otherwise = jDouble pr a p
  where
    z1s = (z1 * z1) `mod` pr
    z2s = (z2 * z2) `mod` pr
    u1 = (x1 * z2s) `mod` pr
    u2 = (x2 * z1s) `mod` pr
    s1 = (y1 * z2s * z2) `mod` pr
    s2 = (y2 * z1s * z1) `mod` pr
    h = (u2 - u1) `mod` pr
    r = (s2 - s1) `mod` pr
    h2 = (h * h) `mod` pr
    h3 = (h2 * h) `mod` pr
    x3 = (r * r - h3 - 2 * u1 * h2) `mod` pr
    y3 = (r * (u1 * h2 - x3) - s1 * h3) `mod` pr
    z3 = (h * z1 * z2) `mod` pr

fromJacobian :: Integer -> JPoint -> Point curve
fromJacobian _ JPointO = PointO
fromJacobian pr (JPoint x y z) =
    case inverse z pr of
        Nothing -> PointO
        Just zi ->
            let zi2 = (zi * zi) `mod` pr
             in Point ((x * zi2) `mod` pr) ((y * zi2 * zi) `mod` pr)

-- | Elliptic curve double-scalar multiplication (uses Shamir's trick).
--
-- > pointAddTwoMuls n1 p1 n2 p2 == pointAdd (pointMul n1 p1)
-- >                                         (pointMul n2 p2)
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAddTwoMuls
    :: forall curve
     . Curve curve
    => Scalar curve -> Point curve -> Scalar curve -> Point curve -> Point curve
pointAddTwoMuls _ PointO _ PointO = PointO
pointAddTwoMuls _ PointO n2 p2 = pointMul n2 p2
pointAddTwoMuls n1 p1 _ PointO = pointMul n1 p1
pointAddTwoMuls s1@(Scalar n1) p1 s2@(Scalar n2) p2
    | n1 < 0 || n2 < 0 = pointAdd (pointMul s1 p1) (pointMul s2 p2)
    | otherwise =
        case curveType (Proxy :: Proxy curve) of
            CurvePrime (CurvePrimeParam pr) -> jacobian pr
            CurveBinary _ -> affine (n1, n2)
  where
    cc = curveParameters (Proxy :: Proxy curve)
    a = curveEccA cc
    p0 = pointAdd p1 p2

    affine (0, 0) = PointO
    affine (k1, k2) =
        let q = pointDouble $ affine (k1 `div` 2, k2 `div` 2)
         in case (odd k1, odd k2) of
                (True, True) -> pointAdd p0 q
                (True, False) -> pointAdd p1 q
                (False, True) -> pointAdd p2 q
                (False, False) -> q

    -- Shamir's trick, with the division deferred as in pointMul.  Both
    -- scalars are public here -- verification is the caller -- so this skips
    -- the addition when a bit is clear rather than adding regardless.
    jacobian pr = fromJacobian pr (go (bits - 1) JPointO)
      where
        bits =
            maximum [integerBits n1, integerBits n2, integerBits (curveEccN cc)]
        j0 = toJacobian p0
        j1 = toJacobian p1
        j2 = toJacobian p2
        go i acc
            | i < 0 = acc
            | otherwise =
                let d = jDouble pr a acc
                 in go (i - 1) $ case (testBit n1 i, testBit n2 i) of
                        (True, True) -> jAdd pr a d j0
                        (True, False) -> jAdd pr a d j1
                        (False, True) -> jAdd pr a d j2
                        (False, False) -> d

toJacobian :: Point curve -> JPoint
toJacobian PointO = JPointO
toJacobian (Point x y) = JPoint x y 1

-- | Check if a point is the point at infinity.
isPointAtInfinity :: Point curve -> Bool
isPointAtInfinity PointO = True
isPointAtInfinity _ = False

-- | Make a point on a curve from integer (x,y) coordinate
--
-- if the point is not valid related to the curve then an error is
-- returned instead of a point
pointFromIntegers
    :: forall curve. Curve curve => (Integer, Integer) -> CryptoFailable (Point curve)
pointFromIntegers (x, y)
    | isPointValid (Proxy :: Proxy curve) x y = CryptoPassed $ Point x y
    | otherwise =
        CryptoFailed $ CryptoError_PointCoordinatesInvalid

-- | check if a point is on specific curve
--
-- This perform three checks:
--
-- * x is not out of range
-- * y is not out of range
-- * the equation @y^2 = x^3 + a*x + b (mod p)@ holds
isPointValid :: Curve curve => proxy curve -> Integer -> Integer -> Bool
isPointValid proxy x y =
    case ty of
        CurvePrime (CurvePrimeParam p) ->
            let a = curveEccA cc
                b = curveEccB cc
                eqModP z1 z2 = (z1 `mod` p) == (z2 `mod` p)
                isValid e = e >= 0 && e < p
             in isValid x && isValid y && (y ^ (2 :: Int)) `eqModP` (x ^ (3 :: Int) + a * x + b)
        CurveBinary (CurveBinaryParam fx) ->
            let a = curveEccA cc
                b = curveEccB cc
                add = addF2m
                mul = mulF2m fx
                isValid e = modF2m fx e == e
             in and
                    [ isValid x
                    , isValid y
                    , ((((x `add` a) `mul` x `add` y) `mul` x) `add` b `add` (squareF2m fx y)) == 0
                    ]
  where
    ty = curveType proxy
    cc = curveParameters proxy

-- | div and mod
divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod y x m = do
    i <- inverse (x `mod` m) m
    return $ y * i `mod` m
