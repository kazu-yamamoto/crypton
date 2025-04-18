{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

module KAT_Camellia (tests) where

import BlockCipher
import Imports ()

import Crypto.Cipher.Camellia
import qualified Data.ByteString as B

vectors_camellia128 =
    [ KAT_ECB
        (B.replicate 16 0)
        (B.replicate 16 0)
        ( B.pack
            [ 0x3d
            , 0x02
            , 0x80
            , 0x25
            , 0xb1
            , 0x56
            , 0x32
            , 0x7c
            , 0x17
            , 0xf7
            , 0x62
            , 0xc1
            , 0xf2
            , 0xcb
            , 0xca
            , 0x71
            ]
        )
    , KAT_ECB
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xab
            , 0xcd
            , 0xef
            , 0xfe
            , 0xdc
            , 0xba
            , 0x98
            , 0x76
            , 0x54
            , 0x32
            , 0x10
            ]
        )
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xab
            , 0xcd
            , 0xef
            , 0xfe
            , 0xdc
            , 0xba
            , 0x98
            , 0x76
            , 0x54
            , 0x32
            , 0x10
            ]
        )
        ( B.pack
            [ 0x67
            , 0x67
            , 0x31
            , 0x38
            , 0x54
            , 0x96
            , 0x69
            , 0x73
            , 0x08
            , 0x57
            , 0x06
            , 0x56
            , 0x48
            , 0xea
            , 0xbe
            , 0x43
            ]
        )
    ]

vectors_camellia192 =
    [ KAT_ECB
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xab
            , 0xcd
            , 0xef
            , 0xfe
            , 0xdc
            , 0xba
            , 0x98
            , 0x76
            , 0x54
            , 0x32
            , 0x10
            , 0x00
            , 0x11
            , 0x22
            , 0x33
            , 0x44
            , 0x55
            , 0x66
            , 0x77
            ]
        )
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xab
            , 0xcd
            , 0xef
            , 0xfe
            , 0xdc
            , 0xba
            , 0x98
            , 0x76
            , 0x54
            , 0x32
            , 0x10
            ]
        )
        ( B.pack
            [ 0xb4
            , 0x99
            , 0x34
            , 0x01
            , 0xb3
            , 0xe9
            , 0x96
            , 0xf8
            , 0x4e
            , 0xe5
            , 0xce
            , 0xe7
            , 0xd7
            , 0x9b
            , 0x09
            , 0xb9
            ]
        )
    ]

vectors_camellia256 =
    [ KAT_ECB
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xab
            , 0xcd
            , 0xef
            , 0xfe
            , 0xdc
            , 0xba
            , 0x98
            , 0x76
            , 0x54
            , 0x32
            , 0x10
            , 0x00
            , 0x11
            , 0x22
            , 0x33
            , 0x44
            , 0x55
            , 0x66
            , 0x77
            , 0x88
            , 0x99
            , 0xaa
            , 0xbb
            , 0xcc
            , 0xdd
            , 0xee
            , 0xff
            ]
        )
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xab
            , 0xcd
            , 0xef
            , 0xfe
            , 0xdc
            , 0xba
            , 0x98
            , 0x76
            , 0x54
            , 0x32
            , 0x10
            ]
        )
        ( B.pack
            [ 0x9a
            , 0xcc
            , 0x23
            , 0x7d
            , 0xff
            , 0x16
            , 0xd7
            , 0x6c
            , 0x20
            , 0xef
            , 0x7c
            , 0x91
            , 0x9e
            , 0x3a
            , 0x75
            , 0x09
            ]
        )
    ]

kats128 = defaultKATs{kat_ECB = vectors_camellia128}
kats192 = defaultKATs{kat_ECB = vectors_camellia192}
kats256 = defaultKATs{kat_ECB = vectors_camellia256}

tests = testBlockCipher kats128 (undefined :: Camellia128)
