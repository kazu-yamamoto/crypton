{-# LANGUAGE OverloadedStrings #-}

module MAC.Poly1305Spec (spec) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B ()

import Crypto.Error
import Imports

import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Data.ByteArray as B (convert)

import qualified MAC.Poly1305Vectors as Vectors

instance Show Poly1305.Auth where
    show _ = "Auth"

-- The key is part of this: with the all-zero key the property below held
-- whatever either side did, r being zero and the tag therefore the nonce --
-- which is how it came to feed the chunks in the wrong order and pass.
data Chunking = Chunking Int Int ByteString
    deriving (Show, Eq)

instance Arbitrary Chunking where
    arbitrary =
        Chunking <$> choose (1, 34) <*> choose (1, 2048) <*> arbitraryBS 32

spec :: Spec
spec = do
    it "V0" $
        let key =
                "\x85\xd6\xbe\x78\x57\x55\x6d\x33\x7f\x44\x52\xfe\x42\xd5\x06\xa8\x01\x03\x80\x8a\xfb\x0d\xb2\xfd\x4a\xbf\xf6\xaf\x41\x49\xf5\x1b"
                    :: ByteString
            msg = "Cryptographic Forum Research Group" :: ByteString
            tag =
                "\xa8\x06\x1d\xc1\x30\x51\x36\xc6\xc2\x2b\x8b\xaf\x0c\x01\x27\xa9" :: ByteString
         in B.convert (Poly1305.auth key msg) `shouldBe` tag
    describe "vectors" $ mapM_ vectorTest Vectors.vectors
    prop "Chunking" $ \(Chunking chunkLen totalLen key) ->
        let msg = B.pack $ take totalLen $ concat (replicate 10 [1 .. 255])
         in Poly1305.auth key msg
                == Poly1305.finalize
                    ( foldl
                        Poly1305.update
                        (throwCryptoError $ Poly1305.initialize key)
                        (chunks chunkLen msg)
                    )
  where
    vectorTest (ki, mi, len, expected) =
        it
            ( "key "
                ++ show ki
                ++ ", message "
                ++ show mi
                ++ ", "
                ++ show len
                ++ " bytes"
            )
            $ B.convert (Poly1305.auth (Vectors.polyKey ki) (Vectors.polyMessage mi len))
                `shouldBe` expected
    chunks i bs
        | B.length bs < i = [bs]
        | otherwise = let (b1, b2) = B.splitAt i bs in b1 : chunks i b2
