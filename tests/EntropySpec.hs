-- | The system source of entropy.
--
-- There is nothing here to check the bytes against -- they are supposed to
-- be unpredictable, and a test that said otherwise would be a test of the
-- kernel.  What can be checked is that the right number of them comes back,
-- which is where an implementation of the call with a limit per request
-- goes wrong: @getentropy(3)@ refuses more than 256 bytes at a time, so a
-- backend that forgets to loop answers a short buffer for anything larger.
module EntropySpec (spec) where

import qualified Data.ByteString as BS
import Data.Maybe (catMaybes)
import Foreign.Marshal.Alloc (allocaBytes)
import Test.Hspec

import Crypto.Random.Entropy (getEntropy)
import Crypto.Random.Entropy.Unsafe (gatherBackend, supportedBackends)

spec :: Spec
spec = describe "the system entropy source" $ do
    mapM_ lengthCase [0, 1, 31, 32, 255, 256, 257, 512, 1000]

    it "does not answer the same thing twice" $ do
        a <- getEntropy 64 :: IO BS.ByteString
        b <- getEntropy 64 :: IO BS.ByteString
        a `shouldNotBe` b

    it "is not answering a constant" $ do
        b <- getEntropy 1024 :: IO BS.ByteString
        BS.length (BS.filter (== BS.head b) b) `shouldSatisfy` (< 64)

    -- getEntropy would not notice: replenish tops a short answer up from
    -- the next backend, so the buffer comes back full either way and the
    -- system call is quietly replaced by the device file.  The backend has
    -- to be asked on its own.
    it "the best backend fills a buffer larger than one request on its own" $ do
        bs <- catMaybes `fmap` sequence supportedBackends
        case bs of
            [] -> expectationFailure "no source of entropy on this system"
            (b : _) -> do
                n <- allocaBytes 1000 $ \ptr -> gatherBackend b ptr 1000
                n `shouldBe` 1000

lengthCase :: Int -> Spec
lengthCase n =
    it ("gives back the " ++ show n ++ " bytes asked for") $ do
        b <- getEntropy n :: IO BS.ByteString
        BS.length b `shouldBe` n
