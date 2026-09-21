{-# LANGUAGE OverloadedStrings #-}

module PubKey.ECCSpec (spec) where

import Crypto.Number.Basic (numBits)
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import Data.Bits (testBit)

import Imports

instance Arbitrary ECC.Curve where
    arbitrary =
        ECC.getCurveByName
            <$> elements
                [ ECC.SEC_p112r1
                , ECC.SEC_p112r2
                , ECC.SEC_p128r1
                , ECC.SEC_p128r2
                , ECC.SEC_p160k1
                , ECC.SEC_p160r1
                , ECC.SEC_p160r2
                , ECC.SEC_p192k1
                , ECC.SEC_p192r1
                , ECC.SEC_p224k1
                , ECC.SEC_p224r1
                , ECC.SEC_p256k1
                , ECC.SEC_p256r1
                , ECC.SEC_p384r1
                , ECC.SEC_p521r1
                , ECC.SEC_t113r1
                , ECC.SEC_t113r2
                , ECC.SEC_t131r1
                , ECC.SEC_t131r2
                , ECC.SEC_t163k1
                , ECC.SEC_t163r1
                , ECC.SEC_t163r2
                , ECC.SEC_t193r1
                , ECC.SEC_t193r2
                , ECC.SEC_t233k1
                , ECC.SEC_t233r1
                , ECC.SEC_t239k1
                , ECC.SEC_t283k1
                , ECC.SEC_t283r1
                , ECC.SEC_t409k1
                , ECC.SEC_t409r1
                , ECC.SEC_t571k1
                , ECC.SEC_t571r1
                ]

data VectorPoint = VectorPoint
    { curve :: ECC.Curve
    , x :: Integer
    , y :: Integer
    , valid :: Bool
    }

vectorsPoint :: [VectorPoint]
vectorsPoint =
    [ VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x491c0c4761b0a4a147b5e4ce03a531546644f5d1e3d05e57
        , y = 0x6fa5addd47c5d6be3933fbff88f57a6c8ca0232c471965de
        , valid = False -- point not on curve
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x646c22e8aa5f7833390e0399155ac198ae42470bba4fc834
        , y = 0x8d4afcfffd80e69a4d180178b37c44572495b7b267ee32a9
        , valid = True
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x4c6b9ea0dec92ecfff7799470be6a2277b9169daf45d54bb
        , y = 0xf0eab42826704f51b26ae98036e83230becb639dd1964627
        , valid = False -- point not on curve
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x0673c8bb717b055c3d6f55c06acfcfb7260361ed3ec0f414
        , y = 0xba8b172826eb0b854026968d2338a180450a27906f6eddea
        , valid = True
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x82c949295156192df0b52480e38c810751ac570daec460a3
        , y = 0x200057ada615c80b8ff256ce8d47f2562b74a438f1921ac3
        , valid = False -- point not on curve
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x284fbaa76ce0faae2ca4867d01092fa1ace5724cd12c8dd0
        , y = 0xe42af3dbf3206be3fcbcc3a7ccaf60c73dc29e7bb9b44fca
        , valid = True
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x1b574acd4fb0f60dde3e3b5f3f0e94211f95112e43cba6fd2
        , y = 0xbcc1b8a770f01a22e84d7f14e44932ffe094d8e3b1e6ac26
        , valid = False -- x or y out of range
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x16ba109f1f1bb44e0d05b80181c03412ea764a59601d17e9f
        , y = 0x0569a843dbb4e287db420d6b9fe30cd7b5d578b052315f56
        , valid = False -- x or y out of range
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x1333308a7c833ede5189d25ea3525919c9bd16370d904938d
        , y = 0xb10fd01d67df75ff9b726c700c1b50596c9f0766ea56f80e
        , valid = False -- x or y out of range
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x9671ec444cff24c8a5be80b018fa505ed6109a731e88c91a
        , y = 0xfe79dae23008e46bf4230c895aab261a95845a77f06d0655
        , valid = True
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0x158e8b6f0b14216bc52fe8897b4305d870ede70436a96741d
        , y = 0xfb3f970b19a313571a1a23be310923f85acc1cab0a157cbd
        , valid = False -- x or y out of range
        }
    , VectorPoint
        { curve = ECC.getCurveByName ECC.SEC_p192r1
        , x = 0xace95b650c08f73dbb4fa7b4bbdebd6b809a25b28ed135ef
        , y = 0xe9b8679404166d1329dd539ad52aad9a1b6681f5f26bb9aa
        , valid = False -- point not on curve
        }
    ]

doPointValidTest :: Show a => a -> VectorPoint -> Spec
doPointValidTest i vector =
    it
        (show i)
        ( ECC.isPointValid (curve vector) (ECC.Point (x vector) (y vector))
            `shouldBe` valid vector
        )

arbitraryPoint :: ECC.Curve -> Gen ECC.Point
arbitraryPoint aCurve =
    frequency [(5, return ECC.PointO), (95, pointGen)]
  where
    n = ECC.ecc_n (ECC.common_curve aCurve)
    pointGen = ECC.pointBaseMul aCurve <$> choose (1, n - 1)

-- | P-256 is the one curve here with a C implementation, and multiplication
-- on it is about to be routed to that.  The properties below cover scalars
-- QuickCheck draws; these are the values at the edges of what a
-- multiplication has to answer for, and the shapes that signature
-- verification uses.
p256Tests :: Spec
p256Tests =
    describe "P-256" $ do
        it "the whole order takes a point to infinity" $
            ECC.pointMul p256curve order g `shouldBe` ECC.PointO
        it "one past the order is one" $
            ECC.pointMul p256curve (order + 1) g `shouldBe` g
        it "a negative scalar is the negation of the positive one" $ do
            ECC.pointMul p256curve (-1) g `shouldBe` ECC.pointNegate p256curve g
            ECC.pointMul p256curve (-7) g
                `shouldBe` ECC.pointNegate p256curve (ECC.pointMul p256curve 7 g)
        it "a scalar past the order wraps" $
            ECC.pointMul p256curve (3 * order + 11) g `shouldBe` ECC.pointMul p256curve 11 g
        it "a scalar wraps on either side of what 256 bits hold" $ do
            -- the order is under 2^256 and twice it is over, so these are the
            -- values around the boundary of a fixed-width reduction
            ECC.pointMul p256curve (order - 1) g
                `shouldBe` ECC.pointNegate p256curve g
            ECC.pointMul p256curve (2 ^ (256 :: Int) - 1) g
                `shouldBe` ECC.pointMul p256curve ((2 ^ (256 :: Int) - 1) `mod` order) g
            ECC.pointMul p256curve (2 ^ (256 :: Int)) g
                `shouldBe` ECC.pointMul p256curve (2 ^ (256 :: Int) `mod` order) g
            ECC.pointMul p256curve (2 * order) g `shouldBe` ECC.PointO
            ECC.pointMul p256curve (2 * order + 3) g `shouldBe` ECC.pointMul p256curve 3 g
        it "zero and the point at infinity give infinity" $ do
            ECC.pointMul p256curve 0 g `shouldBe` ECC.PointO
            ECC.pointMul p256curve 5 ECC.PointO `shouldBe` ECC.PointO
        it "multiplying a point that is not on the p256curve is unchanged" $
            -- the C implementation has no answer for these, so they stay with
            -- the generic code; this pins what that answers
            ECC.pointMul p256curve 5 offCurve
                `shouldBe` ECC.pointMul p256curve 5 offCurve
        it "the arithmetic modulo the order is the plain one" $ do
            -- the C implementation takes 256 bits and the order is under
            -- that, so these cross both the reduction and the fallback
            let pairs =
                    [ (0, 0)
                    , (0, 7)
                    , (1, order - 1)
                    , (order - 1, order - 1)
                    , (order, order)
                    , (order + 1, 2)
                    , (2 ^ (256 :: Int) - 1, 2 ^ (256 :: Int) - 1)
                    , (2 ^ (256 :: Int), 3)
                    , (2 ^ (300 :: Int) + 5, 2 ^ (256 :: Int) + 9)
                    , (-3, 5)
                    , (3, -5)
                    ]
            [ (a, b)
              | (a, b) <- pairs
              , ECC.scalarAdd p256curve a b /= (a + b) `mod` order
                    || ECC.scalarMul p256curve a b /= (a * b) `mod` order
              ]
                `shouldBe` []
        it "two muls is the sum of the muls, base point either side" $ do
            ECC.pointAddTwoMuls p256curve 3 g 5 q
                `shouldBe` ECC.pointAdd
                    p256curve
                    (ECC.pointMul p256curve 3 g)
                    (ECC.pointMul p256curve 5 q)
            ECC.pointAddTwoMuls p256curve 5 q 3 g
                `shouldBe` ECC.pointAdd
                    p256curve
                    (ECC.pointMul p256curve 5 q)
                    (ECC.pointMul p256curve 3 g)
            ECC.pointAddTwoMuls p256curve order g 5 q `shouldBe` ECC.pointMul p256curve 5 q
  where
    p256curve = ECC.getCurveByName ECC.SEC_p256r1
    order = ECC.ecc_n (ECC.common_curve p256curve)
    g = ECC.ecc_g (ECC.common_curve p256curve)
    q = ECC.pointMul p256curve 0x2a3f1c9e g
    offCurve = ECC.Point 1 1

-- | Multiplication the long way, out of the affine addition and doubling,
-- for the fast one to be held to.
doubleAndAdd :: ECC.Curve -> Integer -> ECC.Point -> ECC.Point
doubleAndAdd c k q = go (numBits k - 1) ECC.PointO
  where
    go i acc
        | i < 0 = acc
        | testBit k i = go (i - 1) (ECC.pointAdd c (ECC.pointDouble c acc) q)
        | otherwise = go (i - 1) (ECC.pointDouble c acc)

-- | A scalar multiplication over a prime field walks the bits of the scalar,
-- and what it does at a bit that is set differs from what it does at one that
-- is not.  These are the scalars where that difference is starkest -- one bit
-- set, every bit set, alternating bits -- and what they pin is that all of
-- them still come out right.
weightTests :: Spec
weightTests = describe "scalars of every weight" $ do
    check "P-384" ECC.SEC_p384r1
    check "P-521" ECC.SEC_p521r1
  where
    check name curveName = describe name $ do
        it "adding two scalars is adding their multiples" $
            [ (a, b)
            | (a, b) <- pairs
            , ECC.pointMul c (a + b) g
                /= ECC.pointAdd c (ECC.pointMul c a g) (ECC.pointMul c b g)
            ]
                `shouldBe` []
      where
        c = ECC.getCurveByName curveName
        n = ECC.ecc_n (ECC.common_curve c)
        g = ECC.ecc_g (ECC.common_curve c)
        bits = numBits n
        ones k = 2 ^ k - 1
        alternating k = sum [2 ^ i | i <- [0, 2 .. k]]
        pairs =
            [ (1, 1)
            , (2 ^ (bits - 2), 1)
            , (ones (bits - 2), 1)
            , (alternating (bits - 2), 3)
            , (ones (bits - 2), alternating (bits - 2))
            , (n - 1, n - 1)
            , -- twice the width of the order and more, which is what
              -- recovering a public key hands to a multiplication
              (n * n, 3)
            , (n * n * n, alternating (bits - 2))
            ]

spec :: Spec
spec = do
    describe "valid-point" $ zipWithM_ doPointValidTest [katZero ..] vectorsPoint
    p256Tests
    weightTests
    modifyMaxSuccess (const 20) $
        describe "property" $ do
            prop "point-add" $ \aCurve (QAInteger r1) (QAInteger r2) ->
                let curveN = ECC.ecc_n . ECC.common_curve $ aCurve
                    curveGen = ECC.ecc_g . ECC.common_curve $ aCurve
                    p1 = ECC.pointMul aCurve r1 curveGen
                    p2 = ECC.pointMul aCurve r2 curveGen
                    pR = ECC.pointMul aCurve ((r1 + r2) `mod` curveN) curveGen
                 in pR `propertyEq` ECC.pointAdd aCurve p1 p2
            prop "point-negate-add" $ \aCurve -> do
                p <- arbitraryPoint aCurve
                let o = ECC.pointAdd aCurve p (ECC.pointNegate aCurve p)
                return $ ECC.PointO `propertyEq` o
            prop "point-negate-negate" $ \aCurve -> do
                p <- arbitraryPoint aCurve
                return $ p `propertyEq` ECC.pointNegate aCurve (ECC.pointNegate aCurve p)
            prop "point-mul-mul" $ \aCurve (QAInteger n1) (QAInteger n2) -> do
                p <- arbitraryPoint aCurve
                let pRes = ECC.pointMul aCurve (n1 * n2) p
                let pDef = ECC.pointMul aCurve n1 (ECC.pointMul aCurve n2 p)
                return $ pRes `propertyEq` pDef
            prop "point-mul-matches-double-and-add" $ \aCurve (QAInteger k) ->
                let n = ECC.ecc_n (ECC.common_curve aCurve)
                    g = ECC.ecc_g (ECC.common_curve aCurve)
                    k' = 1 + k `mod` (n - 1)
                 in ECC.pointMul aCurve k' g == doubleAndAdd aCurve k' g
            prop "scalar-arithmetic" $ \aCurve (QAInteger n1) (QAInteger n2) ->
                let n = ECC.ecc_n (ECC.common_curve aCurve)
                 in ECC.scalarAdd aCurve n1 n2
                        == (n1 + n2) `mod` n
                        && ECC.scalarMul aCurve n1 n2
                            == (n1 * n2) `mod` n
            prop "double-scalar-mult" $ \aCurve (QAInteger n1) (QAInteger n2) -> do
                p1 <- arbitraryPoint aCurve
                p2 <- arbitraryPoint aCurve
                let pRes = ECC.pointAddTwoMuls aCurve n1 p1 n2 p2
                let pDef = ECC.pointAdd aCurve (ECC.pointMul aCurve n1 p1) (ECC.pointMul aCurve n2 p2)
                return $ pRes `propertyEq` pDef
