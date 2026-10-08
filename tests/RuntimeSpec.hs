-- | What 'processorOptions' says about the machine it is running on.
--
-- A test cannot know what processor it is on, so it cannot check that the
-- answer is right.  What it can check is that the answer is well formed:
-- that every name is distinct, that nothing is reported under a name from
-- another architecture, and that the two questions which do not name one
-- agree with the list.  The list is printed as well, because a CI log that
-- says what each runner reported is the only way the detection itself gets
-- looked at.
module RuntimeSpec (spec) where

import Data.List (nub, sort)
import Test.Hspec

import Crypto.System.CPU

-- | Every name this module gives, which is also the set 'Show' has to
-- cover.
x86Options :: [ProcessorOption]
x86Options =
    [AESNI, PCLMUL, RDRAND, SSSE3, AVX, AVX2, SHANI, MOVBE, ADX, VAES, VAES512]

armOptions :: [ProcessorOption]
armOptions = [NEON, ARMAES, ARMPMULL, ARMSHA1, ARMSHA2, ARMSHA512]

spec :: Spec
spec = describe "processorOptions" $ do
    it "CPU" $ putStrLn (show processorOptions)

    it "gives every name a number of its own" $
        -- two patterns sharing a number would make one of them unreachable
        -- and the other print under the wrong name
        length (nub (x86Options ++ armOptions))
            `shouldBe` length (x86Options ++ armOptions)

    it "has a name for every option it names" $
        -- Show falls back to "ProcessorOption n" for what it does not know,
        -- which is for values from a newer release, not for these
        filter (startsWith "ProcessorOption " . show) (x86Options ++ armOptions)
            `shouldBe` []

    it "reports each option at most once, in order" $ do
        processorOptions `shouldBe` sort processorOptions
        nub processorOptions `shouldBe` processorOptions

    it "does not mix one architecture's names with another's" $ do
        let anyX86 = any (`elem` x86Options) processorOptions
            anyARM = any (`elem` armOptions) processorOptions
        -- RDRAND is x86's and is in that list, so a machine reporting both
        -- groups is the AArch64-says-AESNI fault this replaced
        (anyX86 && anyARM) `shouldBe` False

    -- Half a check, and which half depends on the machine: where the
    -- processor has AES this fails if the answer is broken to False and
    -- passes if it is broken to True, and the other way round on a machine
    -- without it.  Both were tried.
    it "answers the architecture-free questions from the same list" $ do
        hasAESAcceleration
            `shouldBe` (AESNI `elem` processorOptions || ARMAES `elem` processorOptions)
        hasGHASHAcceleration
            `shouldBe` (PCLMUL `elem` processorOptions || ARMPMULL `elem` processorOptions)

startsWith :: String -> String -> Bool
startsWith p s = take (length p) s == p
