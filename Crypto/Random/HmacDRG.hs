module Crypto.Random.HmacDRG (HmacDRG, initial, update) where

import Data.Maybe
import qualified Data.ByteString as B
import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as M
import Crypto.Hash
import Crypto.MAC.HMAC (HMAC (..), hmac)
import Crypto.Random.Types

-- | HMAC-based Deterministic Random Generator
--
-- Adapted from NIST Special Publication 800-90A Revision 1, Section 10.1.2
data HmacDRG hash = HmacDRG (Digest hash) (Digest hash)

-- | The initial DRG state. It should be seeded via 'update' before use.
initial :: HashAlgorithm hash => hash -> HmacDRG hash
initial algorithm = HmacDRG (constant 0x00) (constant 0x01) where
    constant = fromJust . digestFromByteString . B.replicate (hashDigestSize algorithm)

-- | Update the DRG state with optional provided data.
update :: ByteArrayAccess input => HashAlgorithm hash => input -> HmacDRG hash -> HmacDRG hash
update input state0 = if M.null input then state1 else state2 where
    state1 = step 0x00 state0
    state2 = step 0x01 state1
    step byte (HmacDRG key value) = HmacDRG keyNew valueNew where
        keyNew = hmacGetDigest $ hmac key $ M.convert value <> B.singleton byte <> M.convert input
        valueNew = hmacGetDigest $ hmac keyNew value

instance HashAlgorithm hash => DRG (HmacDRG hash) where
    randomBytesGenerate count (HmacDRG key value) = (output, state) where
        output = M.take count result
        state = update B.empty $ HmacDRG key new
        (result, new) = go M.empty value
        go buffer current
            | M.length buffer >= count = (buffer, current)
            | otherwise = go (buffer <> M.convert next) next
            where next = hmacGetDigest $ hmac key current
