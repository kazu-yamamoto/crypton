-- | Does the generator behind 'MonadRandom' notice a fork made from
-- Haskell?
--
-- @cbits\/tests\/sysdrg@ asks the same question of @fork(2)@ called from C,
-- in a process with no runtime system in it at all.  That leaves the case
-- anyone actually meets untested: 'forkProcess', with the runtime's own
-- threads about.  The handler is registered with @pthread_atfork@, which
-- libc runs for every @fork(2)@ whoever calls it, so it should reach this
-- too -- should, which is why this is a test and not a comment.
--
-- It cannot live in the main suite.  That one runs with @-N2@, where GHC
-- says 'forkProcess' is not supported; this needs its own runtime options,
-- and is built twice, once threaded with one capability and once not
-- threaded at all.  Both are configurations GHC supports 'forkProcess' in.
--
-- The check is that parent and child disagree.  Without fork detection the
-- child carries on the parent's stream, so the next block each of them
-- draws is the same block -- they would agree exactly, which is the fault.
module Main (main) where

import Control.Concurrent (getNumCapabilities, rtsSupportsBoundThreads)
import Control.Monad (when)
import qualified Data.ByteString as B
import System.Exit (exitFailure)
import System.IO (hClose, hFlush, hPutStrLn, stderr, stdout)
import System.Posix.IO (closeFd, createPipe, fdToHandle)
import System.Posix.Process (ProcessStatus (..), forkProcess, getProcessStatus)

import Crypto.Random (getRandomBytes)

draw :: IO B.ByteString
draw = getRandomBytes 32

main :: IO ()
main = do
    caps <- getNumCapabilities
    putStrLn $
        "threaded: "
            ++ show rtsSupportsBoundThreads
            ++ ", capabilities: "
            ++ show caps
    -- GHC supports forkProcess with -threaded only while one capability is
    -- in use.  Saying so here means a change to the runtime options shows
    -- up as a failure rather than as a test that quietly means nothing.
    when (rtsSupportsBoundThreads && caps /= 1) $
        die "this test needs one capability when threaded"

    -- Before the fork, or the child inherits whatever is still in the
    -- buffer and writes it out again when it exits.
    hFlush stdout

    -- Draw once first, so that both sides inherit a generator that has been
    -- seeded.  A child of an unseeded one would seed itself for the first
    -- time and differ for that reason instead of this one.
    _ <- draw

    (readEnd, writeEnd) <- createPipe
    pid <- forkProcess $ do
        closeFd readEnd
        b <- draw
        h <- fdToHandle writeEnd
        B.hPut h b
        hClose h
    closeFd writeEnd
    hr <- fdToHandle readEnd
    fromChild <- B.hGet hr 32
    hClose hr
    status <- getProcessStatus True False pid

    fromParent <- draw

    case status of
        Just (Exited _) -> return ()
        other -> die ("the child did not exit cleanly: " ++ show other)
    when (B.length fromChild /= 32) $
        die ("the child sent " ++ show (B.length fromChild) ++ " bytes, not 32")
    when (fromChild == fromParent) $
        die "parent and child drew the same bytes: the fork went unnoticed"
    putStrLn "parent and child drew different bytes"
  where
    die msg = hPutStrLn stderr ("FAIL: " ++ msg) >> exitFailure
