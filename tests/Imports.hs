module Imports (
    -- * Individual Types
    Word16,
    Word32,
    Word64,
    ByteString,

    -- * Test vectors
    firstVector,

    -- * Modules
    module X,
) where

import Data.ByteString (ByteString)
import Data.Word (Word16, Word32, Word64)

import Control.Applicative as X
import Control.Monad as X
import Data.ByteString.Char8 as X ()
import Data.Foldable as X (foldl')
import Data.Monoid as X

import Test.Hspec as X
import Test.Hspec.QuickCheck as X (modifyMaxSuccess, prop)
import Test.QuickCheck as X hiding (vector)
import Utils as X

-- | The first of a list of test vectors.  The lists these are taken from are
-- literals in the modules that hold them and are never empty, so this says so
-- once, with a name and a message, rather than leaving a partial 'head' at
-- every use.
firstVector :: [a] -> a
firstVector (v : _) = v
firstVector [] = error "firstVector: the vector list is empty"
