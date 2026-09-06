{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module KAT_PubKey.P256 (tests) where

import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC

import Crypto.Error
import Crypto.Number.ModArithmetic (inverseCoprimes)
import Crypto.Number.Serialize (i2ospOf, os2ip)
import Data.ByteArray (Bytes)

import Imports

newtype P256Scalar = P256Scalar Integer
    deriving (Show, Eq, Ord)

instance Arbitrary P256Scalar where
    -- Cover the full range up to 2^256-1 except 0 and curveN.  To test edge
    -- cases with arithmetic functions, some values close to 0, curveN and
    -- 2^256 are given higher frequency.
    arbitrary =
        P256Scalar
            <$> oneof
                [ choose (1, w)
                , choose (w + 1, curveN - w - 1)
                , choose (curveN - w, curveN - 1)
                , choose (curveN + 1, curveN + w)
                , choose (curveN + w + 1, high - w - 1)
                , choose (high - w, high - 1)
                ]
      where
        high = 2 ^ (256 :: Int)
        w = 100

curve = ECC.getCurveByName ECC.SEC_p256r1
curveN = ECC.ecc_n . ECC.common_curve $ curve
curveGen = ECC.ecc_g . ECC.common_curve $ curve

pointP256ToECC :: P256.Point -> ECC.Point
pointP256ToECC p
    | P256.pointIsAtInfinity p = ECC.PointO
    | otherwise = uncurry ECC.Point (P256.pointToIntegers p)

i2ospScalar :: Integer -> Bytes
i2ospScalar i =
    case i2ospOf 32 i of
        Nothing -> error "invalid size of P256 scalar"
        Just b -> b

unP256Scalar :: P256Scalar -> P256.Scalar
unP256Scalar (P256Scalar r) =
    let rBytes = i2ospScalar r
     in case P256.scalarFromBinary rBytes of
            CryptoFailed err -> error ("cannot convert scalar: " ++ show err)
            CryptoPassed scalar -> scalar

unP256 :: P256Scalar -> Integer
unP256 (P256Scalar r) = r

modP256Scalar :: P256Scalar -> P256Scalar
modP256Scalar (P256Scalar r) = P256Scalar (r `mod` curveN)

p256ScalarToInteger :: P256.Scalar -> Integer
p256ScalarToInteger s = os2ip (P256.scalarToBinary s :: Bytes)

xS = 0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9
yS = 0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256
xT = 0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b
yT = 0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316
xR = 0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e
yR = 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264

-- Two points on the curve whose validation reduces a product whose top
-- digit has a zero low half: x = 2^96, and an x with a repeating bit
-- pattern.  Wycheproof ecdh_secp256r1_ecpoint tcId 74 and 93.
xU = 0x0000000000000000000000000000000000000001000000000000000000000000
yU = 0x7d12de58d54423eb85ae8d157ae416fb004a7eb522ac1b67047ef3cdf9acdc3f
xV = 0x8000003ffffff0000007fffffe000000ffffffc000001ffffff8000003fffffc
yV = 0x0c3527bd081c1c07b313bc1a0c3f845fb2fe22557699ccc8f1354e61a27b7f88

validPointEdgeCases :: [(String, (Integer, Integer))]
validPointEdgeCases =
    [ ("x-zero-1", (0, 0x66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4))
    , ("x-zero-2", (0, 0x99b7a386f1d07c29dbcc42a27b5f9449abe3d50de25178e8d7407a95e8b06c0b))
    , ("y-one-1", (0x09e78d4ef60d05f750f6636209092bc43cbdd6b47e11a9de20a9feb2a50bb96c, 1))
    , ("y-one-2", (0x8d0177ebab9c6e9e10db6dd095dbac0d6375e8a97b70f611875d877f0069d2c7, 1))
    , ("y-one-3", (0x6916fac45e568b6b9e2e2ecd611b282e5fcc40a3067d601057f879ce5a8a73cc, 1))
    ]

tests =
    testGroup
        "P256"
        [ testGroup
            "scalar"
            [ testProperty "marshalling" $ \(QAInteger r) ->
                let rBytes = i2ospScalar r
                 in case P256.scalarFromBinary rBytes of
                        CryptoFailed err -> error (show err)
                        CryptoPassed scalar -> rBytes `propertyEq` P256.scalarToBinary scalar
            , testProperty "add" $ \r1 r2 ->
                let r = (unP256 r1 + unP256 r2) `mod` curveN
                    r' = P256.scalarAdd (unP256Scalar r1) (unP256Scalar r2)
                 in r `propertyEq` p256ScalarToInteger r'
            , testProperty "add0" $ \r ->
                let v = unP256 r `mod` curveN
                    v' = P256.scalarAdd (unP256Scalar r) P256.scalarZero
                 in v `propertyEq` p256ScalarToInteger v'
            , testProperty "sub" $ \r1 r2 ->
                let r = (unP256 r1 - unP256 r2) `mod` curveN
                    r' = P256.scalarSub (unP256Scalar r1) (unP256Scalar r2)
                    v = (unP256 r2 - unP256 r1) `mod` curveN
                    v' = P256.scalarSub (unP256Scalar r2) (unP256Scalar r1)
                 in propertyHold
                        [ eqTest "r1-r2" r (p256ScalarToInteger r')
                        , eqTest "r2-r1" v (p256ScalarToInteger v')
                        ]
            , testProperty "sub0" $ \r ->
                let v = unP256 r `mod` curveN
                    v' = P256.scalarSub (unP256Scalar r) P256.scalarZero
                 in v `propertyEq` p256ScalarToInteger v'
            , testProperty "mul" $ \r1 r2 ->
                let r = (unP256 r1 * unP256 r2) `mod` curveN
                    r' = P256.scalarMul (unP256Scalar r1) (unP256Scalar r2)
                 in r `propertyEq` p256ScalarToInteger r'
            , testProperty "inv" $ \r' ->
                let inv = inverseCoprimes (unP256 r') curveN
                    inv' = P256.scalarInv (unP256Scalar r')
                 in unP256 r' /= 0 ==> inv `propertyEq` p256ScalarToInteger inv'
            , testProperty "inv-safe" $ \r' ->
                let inv = P256.scalarInv (unP256Scalar r')
                    inv' = P256.scalarInvSafe (unP256Scalar r')
                 in unP256 r' /= 0 ==> inv `propertyEq` inv'
            , testProperty "inv-safe-mul" $ \r' ->
                let inv = P256.scalarInvSafe (unP256Scalar r')
                    res = P256.scalarMul (unP256Scalar r') inv
                 in unP256 r' /= 0 ==> 1 `propertyEq` p256ScalarToInteger res
            , testProperty "inv-safe-zero" $
                let inv0 = P256.scalarInvSafe P256.scalarZero
                    invN = P256.scalarInvSafe P256.scalarN
                 in propertyHold
                        [ eqTest "scalarZero" P256.scalarZero inv0
                        , eqTest "scalarN" P256.scalarZero invN
                        ]
            ]
        , testGroup
            "point"
            [ testProperty "marshalling" $ \rx ry ->
                let p = P256.pointFromIntegers (unP256 rx, unP256 ry)
                    b = P256.pointToBinary p :: Bytes
                    p' = P256.unsafePointFromBinary b
                 in propertyHold [eqTest "point" (CryptoPassed p) p']
            , testProperty "marshalling-integer" $ \rx ry ->
                let p = P256.pointFromIntegers (unP256 rx, unP256 ry)
                    (x, y) = P256.pointToIntegers p
                 in propertyHold [eqTest "x" (unP256 rx) x, eqTest "y" (unP256 ry) y]
            , testCase "valid-point-1" $ casePointIsValid (xS, yS)
            , testCase "valid-point-2" $ casePointIsValid (xR, yR)
            , testCase "valid-point-3" $ casePointIsValid (xT, yT)
            , -- The quotient estimate in crypton_p256_modmul can exceed the
              -- true quotient, and the resulting borrow used to abort the
              -- process on an assertion inside the reduction rather than
              -- being corrected.  Both points below are on the curve.
              testCase "valid-point-reduction-1" $ casePointIsValid (xU, yU)
            , testCase "valid-point-reduction-2" $ casePointIsValid (xV, yV)
            , testGroup "valid-point-edge-cases" $
                map (\(name, point) -> testCase name $ casePointIsValid point) validPointEdgeCases
            , testCase "point-add-1" $
                let s = P256.pointFromIntegers (xS, yS)
                    t = P256.pointFromIntegers (xT, yT)
                    r = P256.pointFromIntegers (xR, yR)
                 in r @=? P256.pointAdd s t
            , testProperty "point-add-infinity" casePointAddInfinity
            , testProperty "lift-to-curve" propertyLiftToCurve
            , testProperty "point-add" propertyPointAdd
            , testProperty "point-add-infinity-identity" propertyPointAddInfinityIdentity
            , testProperty "point-add-inverse" propertyPointAddInverse
            , testProperty "point-negate" propertyPointNegate
            , testProperty "point-mul" propertyPointMul
            , testProperty "infinity" $
                let gN = P256.toPoint P256.scalarN
                    g1 = P256.pointBase
                 in propertyHold
                        [ eqTest "zero" True (P256.pointIsAtInfinity gN)
                        , eqTest "base" False (P256.pointIsAtInfinity g1)
                        ]
            ]
        ]
  where
    casePointIsValid pointTuple =
        let s = P256.pointFromIntegers pointTuple in True @=? P256.pointIsValid s

    propertyLiftToCurve r =
        let p = P256.toPoint (unP256Scalar r)
            (x, y) = P256.pointToIntegers p
            pEcc = ECC.pointMul curve (unP256 r) curveGen
         in pEcc `propertyEq` ECC.Point x y

    propertyPointAdd r1 r2 =
        let p1 = P256.toPoint (unP256Scalar r1)
            p2 = P256.toPoint (unP256Scalar r2)
            pe1 = ECC.pointMul curve (unP256 r1) curveGen
            pe2 = ECC.pointMul curve (unP256 r2) curveGen
            pR = P256.toPoint (P256.scalarAdd (unP256Scalar r1) (unP256Scalar r2))
            peR = ECC.pointAdd curve pe1 pe2
         in (unP256 r1 + unP256 r2) `mod` curveN
                /= 0
                    ==> propertyHold
                        [ eqTest "p256" pR (P256.pointAdd p1 p2)
                        , eqTest "ecc" peR (pointP256ToECC pR)
                        ]

    propertyPointNegate r =
        let p = P256.toPoint (unP256Scalar r)
            pe = ECC.pointMul curve (unP256 r) curveGen
            pR = P256.pointNegate p
         in ECC.pointNegate curve pe `propertyEq` pointP256ToECC pR

    propertyPointMul s' r' =
        let s = modP256Scalar s'
            r = modP256Scalar r'
            p = P256.toPoint (unP256Scalar r)
            pe = ECC.pointMul curve (unP256 r) curveGen
            pR = P256.toPoint (P256.scalarMul (unP256Scalar s) (unP256Scalar r))
            peR = ECC.pointMul curve (unP256 s) pe
         in propertyHold
                [ eqTest "p256" pR (P256.pointMul (unP256Scalar s) p)
                , eqTest "ecc" peR (pointP256ToECC pR)
                ]

    pointInfinity :: P256.Point
    pointInfinity = P256.pointFromIntegers (0, 0)

    casePointAddInfinity =
        propertyHold
            [ eqTest
                "infinity + base"
                P256.pointBase
                (P256.pointAdd pointInfinity P256.pointBase)
            , eqTest
                "base + infinity"
                P256.pointBase
                (P256.pointAdd P256.pointBase pointInfinity)
            , eqTest
                "infinity + infinity"
                pointInfinity
                (P256.pointAdd pointInfinity pointInfinity)
            ]

    propertyPointAddInfinityIdentity r =
        let p = P256.toPoint (unP256Scalar r)
         in propertyHold
                [ eqTest
                    "infinity + p"
                    p
                    (P256.pointAdd pointInfinity p)
                , eqTest
                    "p + infinity"
                    p
                    (P256.pointAdd p pointInfinity)
                ]

    propertyPointAddInverse r =
        let p = P256.toPoint (unP256Scalar r)
         in propertyHold
                [ eqTest
                    "p + negate p"
                    True
                    (P256.pointIsAtInfinity (P256.pointAdd p (P256.pointNegate p)))
                , eqTest
                    "negate p + p"
                    True
                    (P256.pointIsAtInfinity (P256.pointAdd (P256.pointNegate p) p))
                ]
