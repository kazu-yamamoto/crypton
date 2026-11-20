{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Crypto.PubKey.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
module Crypto.PubKey.Internal (
    and',
    (&&!),
    dsaTruncHash,
    dsaTruncHashDigest,
    getHashAlg,
    rfc6979Nonce,
    rfc6979Generate,
) where

import Data.Bits (shiftR, xor)
import qualified Data.List as L
import Data.Word (Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (poke)

import Crypto.Hash
import Crypto.Hash.Types (HashAlgorithm (..), updateBlocks)
import Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Number.Basic (numBits)
import Crypto.Number.Generate (generatePrefix)
import Crypto.Number.Serialize
import Crypto.Random.HmacDRG (initial, update)
import Crypto.Random.Types (withDRG)
import Data.Memory.PtrMethods (memCopy, memSet, memXorWith)

-- | This is a strict version of and
and' :: [Bool] -> Bool
and' l = L.foldl' (&&!) True l

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
True &&! True = True
True &&! False = False
False &&! True = False
False &&! False = False

-- | Truncate and hash for DSA and ECDSA.
dsaTruncHash
    :: (ByteArrayAccess msg, HashAlgorithm hash) => hash -> msg -> Integer -> Integer
dsaTruncHash hashAlg = dsaTruncHashDigest . hashWith hashAlg

-- | Truncate a digest for DSA and ECDSA.
dsaTruncHashDigest :: HashAlgorithm hash => Digest hash -> Integer -> Integer
dsaTruncHashDigest digest n
    | d > 0 = shiftR e d
    | otherwise = e
  where
    e = os2ip digest
    d = hashDigestSize (getHashAlg digest) * 8 - numBits n

getHashAlg :: Digest hash -> hash
getHashAlg _ = undefined

-- | The nonce of RFC 6979 for a group of order @n@ and private key @x@.
--
-- @extra@ is the additional input of RFC 6979 section 3.6, appended after
-- the digest: empty gives deterministic (EC)DSA, fresh random bytes give a
-- hedged nonce, which is distinct whenever either the randomness or the
-- message is.  @go@ answering 'Nothing' draws the next candidate.
rfc6979Nonce
    :: (HashAlgorithm hashDRG, HashAlgorithm hashDigest)
    => hashDRG
    -> Integer
    -> Integer
    -> Digest hashDigest
    -> ScrubbedBytes
    -> (Integer -> Maybe a)
    -> a
rfc6979Nonce alg n x digest extra go =
    rfc6979Generate alg bits seed $ \k ->
        if 0 < k && k < n then go k else Nothing
  where
    -- int2octets(x) || bits2octets(h1) || k'
    seed = B.concat [i2ospOf_ bytes x, i2ospOf_ bytes h1, extra] :: ScrubbedBytes
    h1 = dsaTruncHashDigest digest n `mod` n
    bytes = (bits + 7) `div` 8
    bits = numBits n

-- | The HMAC_DRBG of RFC 6979 section 3.2, seeded (steps d and f) with
-- @seed@, giving bits2int of each @qlen@-bit candidate (step h) to @go@
-- until it answers.
--
-- The HMACs under one K share its ipad and opad contexts, which are built
-- once per K; going through 'Crypto.MAC.HMAC' builds them per HMAC.
rfc6979Generate
    :: forall hash a
     . HashAlgorithm hash
    => hash -> Int -> ScrubbedBytes -> (Integer -> Maybe a) -> a
rfc6979Generate alg qlen seed go
    | dsize > bsize = slow
    | otherwise = unsafeDoIO $
        allocaBytes dsize $ \kp ->
            allocaBytes dsize $ \vp ->
                allocaBytes dsize $ \ip ->
                    allocaBytes bsize $ \pad ->
                        allocaBytes (3 * csize) $ \ctxs ->
                            allocaBytes 2 $ \sep ->
                                run kp vp ip pad (castPtr ctxs) sep
  where
    bsize = hashBlockSize alg
    dsize = hashDigestSize alg
    csize = hashInternalContextSize alg
    tlen = (qlen + 7) `div` 8

    run
        :: Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr Word8
        -> Ptr (Context hash)
        -> Ptr Word8
        -> IO a
    run kp vp ip pad ictx sep = do
        let octx = ictx `plusPtr` csize :: Ptr (Context hash)
            wctx = ictx `plusPtr` (2 * csize) :: Ptr (Context hash)
            -- the ipad and opad contexts of the current K
            rekey = do
                memSet pad 0 bsize
                memCopy pad kp dsize
                memXorWith pad 0x36 pad bsize
                hashInternalInit ictx
                updateBlocks ictx bsize pad
                memXorWith pad (0x36 `xor` 0x5c) pad bsize
                hashInternalInit octx
                updateBlocks octx bsize pad
            -- HMAC_K over the parts, into out, which may be one of them
            mac parts out = do
                memCopy (castPtr wctx) (castPtr ictx) csize
                mapM_ (\(p, l) -> updateBlocks wctx l p) parts
                hashInternalFinalize wctx (castPtr ip)
                memCopy (castPtr wctx) (castPtr octx) csize
                updateBlocks wctx dsize ip
                hashInternalFinalize wctx (castPtr out)
            v = (vp, dsize)
            zero = (sep, 1)
            one = (sep `plusPtr` 1, 1)
            candidate = do
                t <- B.alloc tlen $ \tp ->
                    let fill off
                            | off >= tlen = return ()
                            | otherwise = do
                                mac [v] vp
                                memCopy (tp `plusPtr` off) vp (min dsize (tlen - off))
                                fill (off + dsize)
                     in fill 0
                return $ os2ip (t :: ScrubbedBytes) `shiftR` (8 * tlen - qlen)
            loop = do
                k <- candidate
                case go k of
                    Just r -> return r
                    Nothing -> do
                        mac [v, zero] kp
                        rekey
                        mac [v] vp
                        loop
        poke sep (0 :: Word8)
        poke (sep `plusPtr` 1) (1 :: Word8)
        memSet vp 1 dsize
        memSet kp 0 dsize
        rekey
        B.withByteArray seed $ \sp -> do
            let s = (sp, B.length seed)
            mac [v, zero, s] kp
            rekey
            mac [v] vp
            mac [v, one, s] kp
            rekey
            mac [v] vp
        r <- loop
        mapM_
            (\(p, l) -> memSet p 0 l)
            [(kp, dsize), (vp, dsize), (ip, dsize), (pad, bsize), (castPtr ictx, 3 * csize)]
        return r

    -- a digest longer than the block would have to be hashed as a key
    slow = fst $ withDRG (update seed $ initial alg) slowRun
    slowRun = do
        k <- generatePrefix qlen
        maybe slowRun pure (go k)
