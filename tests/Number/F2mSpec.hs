module Number.F2mSpec (spec) where

import Crypto.Number.Basic (log2)
import Crypto.Number.F2m
import Data.Bits
import Data.Maybe
import Imports hiding ((.&.))

addTests =
    describe "addF2m" $ do
        prop "commutative" $
            \a b -> a `addF2m` b == b `addF2m` a
        prop "associative" $
            \a b c -> (a `addF2m` b) `addF2m` c == a `addF2m` (b `addF2m` c)
        prop "0 is neutral" $
            \a -> a `addF2m` 0 == a
        prop "nullable" $
            \a -> a `addF2m` a == 0
        prop "works per bit" $
            \a b -> (a `addF2m` b) .&. b == (a .&. b) `addF2m` b

modTests =
    describe "modF2m" $ do
        prop "idempotent" $
            \(Positive m) (NonNegative a) -> modF2m m a == modF2m m (modF2m m a)
        prop "upper bound" $
            \(Positive m) (NonNegative a) -> modF2m m a < 2 ^ log2 m
        prop "reach upper" $
            \(Positive m) -> let a = 2 ^ log2 m - 1 in modF2m m (m `addF2m` a) == a
        prop "lower bound" $
            \(Positive m) (NonNegative a) -> modF2m m a >= 0
        prop "reach lower" $
            \(Positive m) -> modF2m m m == 0
        prop "additive" $
            \(Positive m) (NonNegative a) (NonNegative b) ->
                modF2m m a `addF2m` modF2m m b == modF2m m (a `addF2m` b)

mulTests =
    describe "mulF2m" $ do
        prop "commutative" $
            \(Positive m) (NonNegative a) (NonNegative b) -> mulF2m m a b == mulF2m m b a
        prop "associative" $
            \(Positive m) (NonNegative a) (NonNegative b) (NonNegative c) ->
                mulF2m m (mulF2m m a b) c == mulF2m m a (mulF2m m b c)
        prop "1 is neutral" $
            \(Positive m) (NonNegative a) -> mulF2m m a 1 == modF2m m a
        prop "0 is annihilator" $
            \(Positive m) (NonNegative a) -> mulF2m m a 0 == 0
        prop "distributive" $
            \(Positive m) (NonNegative a) (NonNegative b) (NonNegative c) ->
                mulF2m m a (b `addF2m` c) == mulF2m m a b `addF2m` mulF2m m a c

squareTests =
    describe "squareF2m" $ do
        prop "sqr(a) == a * a" $
            \(Positive m) (NonNegative a) -> mulF2m m a a == squareF2m m a
        -- disabled because we require @m@ to be a suitable modulus and there is no
        -- way to guarantee this
        -- , prop "sqrt(a) * sqrt(a) = a"
        --     $ \(Positive m) (NonNegative aa) -> let a = sqrtF2m m aa in mulF2m m a a == modF2m m aa
        prop "sqrt(a) * sqrt(a) = a in GF(2^16)" $
            let m = 65581 :: Integer -- x^16 + x^5 + x^3 + x^2 + 1
                nums = [0 .. 65535 :: Integer]
             in nums == [let y = sqrtF2m m x in squareF2m m y | x <- nums]

powTests =
    describe "powF2m" $ do
        prop "2 is square" $
            \(Positive m) (NonNegative a) -> powF2m m a 2 == squareF2m m a
        prop "1 is identity" $
            \(Positive m) (NonNegative a) -> powF2m m a 1 == modF2m m a
        prop "0 is annihilator" $
            \(Positive m) (NonNegative a) -> powF2m m a 0 == modF2m m 1
        prop "(a * b) ^ c == (a ^ c) * (b ^ c)" $
            \(Positive m) (NonNegative a) (NonNegative b) (NonNegative c) ->
                powF2m m (mulF2m m a b) c == mulF2m m (powF2m m a c) (powF2m m b c)
        prop "a ^ (b + c) == (a ^ b) * (a ^ c)" $
            \(Positive m) (NonNegative a) (NonNegative b) (NonNegative c) ->
                powF2m m a (b + c) == mulF2m m (powF2m m a b) (powF2m m a c)
        prop "a ^ (b * c) == (a ^ b) ^ c" $
            \(Positive m) (NonNegative a) (NonNegative b) (NonNegative c) ->
                powF2m m a (b * c) == powF2m m (powF2m m a b) c

invTests =
    describe "invF2m" $ do
        prop "1 / a * a == 1" $
            \(Positive m) (NonNegative a) ->
                maybe True (\c -> mulF2m m c a == modF2m m 1) (invF2m m a)
        prop "1 / a == a (mod a^2-1)" $
            \(NonNegative a) -> a < 2 || invF2m (squareF2m' a `addF2m` 1) a == Just a

divTests =
    describe "divF2m" $ do
        prop "1 / a == inv a" $
            \(Positive m) (NonNegative a) -> divF2m m 1 a == invF2m m a
        prop "a / b == a * inv b" $
            \(Positive m) (NonNegative a) (NonNegative b) ->
                divF2m m a b == (mulF2m m a <$> invF2m m b)
        prop "a * b / b == a" $
            \(Positive m) (NonNegative a) (NonNegative b) ->
                isNothing (invF2m m b) || divF2m m (mulF2m m a b) b == Just (modF2m m a)

spec :: Spec
spec = do
    addTests
    modTests
    mulTests
    squareTests
    powTests
    invTests
    divTests
