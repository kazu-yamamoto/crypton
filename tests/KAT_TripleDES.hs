{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module KAT_TripleDES (tests) where

import BlockCipher
import qualified Crypto.Cipher.TripleDES as TripleDES
import Imports

kats = defaultKATs

tests =
    localOption (QuickCheckTests 5) $
        testBlockCipher kats (undefined :: TripleDES.DES_EEE3)
