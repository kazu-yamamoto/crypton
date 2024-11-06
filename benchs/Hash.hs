{-# LANGUAGE PackageImports #-}

module Main where

import qualified Data.ByteString.Lazy as L
import System.Environment
import qualified "cryptohash" Crypto.Hash as Old
import "cryptonite" Crypto.Hash

main = do
    args <- getArgs
    case args of
        [] -> error "usage: bench <big-file>"
        "old" : x : _ -> do
            r <- L.readFile x
            let d = Old.hashlazy r :: Old.Digest Old.SHA1
            putStrLn $ show d
        x : _ -> do
            r <- L.readFile x
            let d = hashlazy r :: Digest SHA1
            putStrLn $ show d
