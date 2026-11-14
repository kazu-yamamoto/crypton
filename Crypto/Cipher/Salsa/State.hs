{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.Cipher.Salsa.State
-- License     : BSD-style
-- Stability   : stable
-- Portability : good
--
-- The Salsa context, shared by Salsa and XSalsa.  The constructor stays in
-- this hidden module: C trusts the size and the offsets inside the bytes.
module Crypto.Cipher.Salsa.State (State (..)) where

import Crypto.Internal.ByteArray (ScrubbedBytes)
import Crypto.Internal.Imports

-- | Salsa context
newtype State = State ScrubbedBytes
    deriving (NFData)
