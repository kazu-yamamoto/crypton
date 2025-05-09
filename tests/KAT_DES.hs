{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module KAT_DES (tests) where

import BlockCipher
import qualified Crypto.Cipher.DES as DES
import Imports

vectors_ecb =
    -- key plaintext ciphertext
    [ KAT_ECB
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7"
    , KAT_ECB
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        "\x73\x59\xB2\x16\x3E\x4E\xDC\x58"
    , KAT_ECB
        "\x30\x00\x00\x00\x00\x00\x00\x00"
        "\x10\x00\x00\x00\x00\x00\x00\x01"
        "\x95\x8E\x6E\x62\x7A\x05\x55\x7B"
    , KAT_ECB
        "\x11\x11\x11\x11\x11\x11\x11\x11"
        "\x11\x11\x11\x11\x11\x11\x11\x11"
        "\xF4\x03\x79\xAB\x9E\x0E\xC5\x33"
    , KAT_ECB
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\x11\x11\x11\x11\x11\x11\x11\x11"
        "\x17\x66\x8D\xFC\x72\x92\x53\x2D"
    , KAT_ECB
        "\x11\x11\x11\x11\x11\x11\x11\x11"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\x8A\x5A\xE1\xF8\x1A\xB8\xF2\xDD"
    , KAT_ECB
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7"
    , KAT_ECB
        "\xFE\xDC\xBA\x98\x76\x54\x32\x10"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\xED\x39\xD9\x50\xFA\x74\xBC\xC4"
    , KAT_ECB
        "\x7C\xA1\x10\x45\x4A\x1A\x6E\x57"
        "\x01\xA1\xD6\xD0\x39\x77\x67\x42"
        "\x69\x0F\x5B\x0D\x9A\x26\x93\x9B"
    , KAT_ECB
        "\x01\x31\xD9\x61\x9D\xC1\x37\x6E"
        "\x5C\xD5\x4C\xA8\x3D\xEF\x57\xDA"
        "\x7A\x38\x9D\x10\x35\x4B\xD2\x71"
    , KAT_ECB
        "\x07\xA1\x13\x3E\x4A\x0B\x26\x86"
        "\x02\x48\xD4\x38\x06\xF6\x71\x72"
        "\x86\x8E\xBB\x51\xCA\xB4\x59\x9A"
    , KAT_ECB
        "\x38\x49\x67\x4C\x26\x02\x31\x9E"
        "\x51\x45\x4B\x58\x2D\xDF\x44\x0A"
        "\x71\x78\x87\x6E\x01\xF1\x9B\x2A"
    , KAT_ECB
        "\x04\xB9\x15\xBA\x43\xFE\xB5\xB6"
        "\x42\xFD\x44\x30\x59\x57\x7F\xA2"
        "\xAF\x37\xFB\x42\x1F\x8C\x40\x95"
    , KAT_ECB
        "\x01\x13\xB9\x70\xFD\x34\xF2\xCE"
        "\x05\x9B\x5E\x08\x51\xCF\x14\x3A"
        "\x86\xA5\x60\xF1\x0E\xC6\xD8\x5B"
    , KAT_ECB
        "\x01\x70\xF1\x75\x46\x8F\xB5\xE6"
        "\x07\x56\xD8\xE0\x77\x47\x61\xD2"
        "\x0C\xD3\xDA\x02\x00\x21\xDC\x09"
    , KAT_ECB
        "\x43\x29\x7F\xAD\x38\xE3\x73\xFE"
        "\x76\x25\x14\xB8\x29\xBF\x48\x6A"
        "\xEA\x67\x6B\x2C\xB7\xDB\x2B\x7A"
    , KAT_ECB
        "\x07\xA7\x13\x70\x45\xDA\x2A\x16"
        "\x3B\xDD\x11\x90\x49\x37\x28\x02"
        "\xDF\xD6\x4A\x81\x5C\xAF\x1A\x0F"
    , KAT_ECB
        "\x04\x68\x91\x04\xC2\xFD\x3B\x2F"
        "\x26\x95\x5F\x68\x35\xAF\x60\x9A"
        "\x5C\x51\x3C\x9C\x48\x86\xC0\x88"
    , KAT_ECB
        "\x37\xD0\x6B\xB5\x16\xCB\x75\x46"
        "\x16\x4D\x5E\x40\x4F\x27\x52\x32"
        "\x0A\x2A\xEE\xAE\x3F\xF4\xAB\x77"
    , KAT_ECB
        "\x1F\x08\x26\x0D\x1A\xC2\x46\x5E"
        "\x6B\x05\x6E\x18\x75\x9F\x5C\xCA"
        "\xEF\x1B\xF0\x3E\x5D\xFA\x57\x5A"
    , KAT_ECB
        "\x58\x40\x23\x64\x1A\xBA\x61\x76"
        "\x00\x4B\xD6\xEF\x09\x17\x60\x62"
        "\x88\xBF\x0D\xB6\xD7\x0D\xEE\x56"
    , KAT_ECB
        "\x02\x58\x16\x16\x46\x29\xB0\x07"
        "\x48\x0D\x39\x00\x6E\xE7\x62\xF2"
        "\xA1\xF9\x91\x55\x41\x02\x0B\x56"
    , KAT_ECB
        "\x49\x79\x3E\xBC\x79\xB3\x25\x8F"
        "\x43\x75\x40\xC8\x69\x8F\x3C\xFA"
        "\x6F\xBF\x1C\xAF\xCF\xFD\x05\x56"
    , KAT_ECB
        "\x4F\xB0\x5E\x15\x15\xAB\x73\xA7"
        "\x07\x2D\x43\xA0\x77\x07\x52\x92"
        "\x2F\x22\xE4\x9B\xAB\x7C\xA1\xAC"
    , KAT_ECB
        "\x49\xE9\x5D\x6D\x4C\xA2\x29\xBF"
        "\x02\xFE\x55\x77\x81\x17\xF1\x2A"
        "\x5A\x6B\x61\x2C\xC2\x6C\xCE\x4A"
    , KAT_ECB
        "\x01\x83\x10\xDC\x40\x9B\x26\xD6"
        "\x1D\x9D\x5C\x50\x18\xF7\x28\xC2"
        "\x5F\x4C\x03\x8E\xD1\x2B\x2E\x41"
    , KAT_ECB
        "\x1C\x58\x7F\x1C\x13\x92\x4F\xEF"
        "\x30\x55\x32\x28\x6D\x6F\x29\x5A"
        "\x63\xFA\xC0\xD0\x34\xD9\xF7\x93"
    , KAT_ECB
        "\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\x61\x7B\x3A\x0C\xE8\xF0\x71\x00"
    , KAT_ECB
        "\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\xDB\x95\x86\x05\xF8\xC8\xC6\x06"
    , KAT_ECB
        "\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE"
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\xED\xBF\xD1\xC6\x6C\x29\xCC\xC7"
    , KAT_ECB
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        "\x35\x55\x50\xB2\x15\x0E\x24\x51"
    , KAT_ECB
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\xCA\xAA\xAF\x4D\xEA\xF1\xDB\xAE"
    , KAT_ECB
        "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\xD5\xD4\x4F\xF7\x20\x68\x3D\x0D"
    , KAT_ECB
        "\xFE\xDC\xBA\x98\x76\x54\x32\x10"
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        "\x2A\x2B\xB0\x08\xDF\x97\xC2\xF2"
    ]

kats = defaultKATs{kat_ECB = vectors_ecb}

tests =
    localOption (QuickCheckTests 5) $
        testBlockCipher kats (undefined :: DES.DES)
