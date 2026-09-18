module RuntimeSpec (spec) where

import Crypto.System.CPU
import Test.Hspec

spec :: Spec
spec = it "CPU" $ putStrLn (show processorOptions)
