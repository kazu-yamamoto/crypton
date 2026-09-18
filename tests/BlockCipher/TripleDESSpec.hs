{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module BlockCipher.TripleDESSpec (spec) where

import BlockCipher
import qualified Crypto.Cipher.TripleDES as TripleDES
import Imports

kats = defaultKATs

spec :: Spec
spec =
    modifyMaxSuccess (const 5) $
        testBlockCipher kats (undefined :: TripleDES.DES_EEE3)
