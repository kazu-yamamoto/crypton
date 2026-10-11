-- | The generator behind 'MonadRandom' for 'IO'.
--
-- What can be asked from Haskell is narrow.  A @forkIO@ thread is not an
-- operating system thread, and this process cannot fork, so the questions
-- that matter most -- does a new operating system thread start its own
-- stream, does a child after @fork@ diverge from its parent -- are in
-- @cbits\/tests\/sysdrg@ instead.
--
-- What is left is still worth asking: the generator keeps a lock and a
-- thread-local slot, and it is reached through a @safe@ foreign call, so
-- many Haskell threads drawing at once is exactly the shape that deadlocks
-- or hands two of them the same bytes.  That needs @-threaded@ and more
-- than one capability, which is why the suite has them.
module SysDRGSpec (spec) where

import Control.Concurrent (
    forkIO,
    getNumCapabilities,
    setNumCapabilities,
    yield,
 )
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (finally)
import Control.Monad (forM, forM_)
import qualified Data.ByteString as BS
import Data.List (group, nub, sort)
import Test.Hspec

import Crypto.Random (getRandomBytes)

spec :: Spec
spec = describe "the generator behind MonadRandom IO" $ do
    it "runs on more than one capability, or the rest proves little" $ do
        n <- getNumCapabilities
        n `shouldSatisfy` (> 1)

    mapM_ lengthCase [0, 1, 32, 1000, 4096]

    it "gives every thread something different" $ do
        -- plainly, rather than through async, which is not a dependency here
        boxes <- forM [1 .. 256 :: Int] $ \_ -> do
            box <- newEmptyMVar
            _ <- forkIO $ do
                b <- getRandomBytes 32 :: IO BS.ByteString
                putMVar box b
            return box
        bss <- mapM takeMVar boxes
        length (nub bss) `shouldBe` 256

    it "keeps the streams apart while setNumCapabilities changes underneath" $ do
        -- The state is held against the operating system thread rather than
        -- against the capability, which is what makes this safe: a forkIO
        -- thread moves between capabilities, and a capability is served by
        -- different worker threads over its life, so state held against one
        -- would be shared by threads running at the same time.  Raising the
        -- count makes the runtime create worker threads, each of which has
        -- to start its own stream; lowering it disables capabilities under
        -- threads that are drawing.
        n0 <- getNumCapabilities
        let flips = concat (replicate 3 [1, 2, min 8 (n0 * 2), n0])
            threads = 64 :: Int
            draws = 16 :: Int
        bss <-
            ( do
                flipped <- newEmptyMVar
                _ <- forkIO $ do
                    forM_ flips $ \n -> setNumCapabilities n >> yield
                    putMVar flipped ()
                boxes <- forM [1 .. threads] $ \_ -> do
                    box <- newEmptyMVar
                    _ <- forkIO $ do
                        bs <- forM [1 .. draws] $ \_ -> do
                            b <- getRandomBytes 32 :: IO BS.ByteString
                            yield
                            return b
                        putMVar box bs
                    return box
                bss <- concat <$> mapM takeMVar boxes
                takeMVar flipped
                return bss
            )
                `finally` setNumCapabilities n0
        -- sorted and grouped rather than nub, which is quadratic and this
        -- list is long enough for that to show
        length bss `shouldBe` threads * draws
        length (group (sort bss)) `shouldBe` threads * draws

    it "does not repeat across a reseed" $ do
        -- the per-thread generator reseeds after a mebibyte
        first <- getRandomBytes 32 :: IO BS.ByteString
        forM_ [1 .. 300 :: Int] $ \_ ->
            (getRandomBytes 4096 :: IO BS.ByteString) >>= \b -> b `seq` return ()
        second <- getRandomBytes 32 :: IO BS.ByteString
        second `shouldNotBe` first

lengthCase :: Int -> Spec
lengthCase n =
    it ("gives back the " ++ show n ++ " bytes asked for") $ do
        b <- getRandomBytes n :: IO BS.ByteString
        BS.length b `shouldBe` n
