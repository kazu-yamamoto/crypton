module KAT_Twofish (tests) where

import BlockCipher
import Imports

import Crypto.Cipher.Twofish
import qualified Data.ByteString as B

vectors_twofish128 =
    [ KAT_ECB
        (B.replicate 16 0x00)
        (B.replicate 16 0x00)
        ( B.pack
            [ 0x9F
            , 0x58
            , 0x9F
            , 0x5C
            , 0xF6
            , 0x12
            , 0x2C
            , 0x32
            , 0xB6
            , 0xBF
            , 0xEC
            , 0x2F
            , 0x2A
            , 0xE8
            , 0xC3
            , 0x5A
            ]
        )
    , KAT_ECB
        ( B.pack
            [ 0x9F
            , 0x58
            , 0x9F
            , 0x5C
            , 0xF6
            , 0x12
            , 0x2C
            , 0x32
            , 0xB6
            , 0xBF
            , 0xEC
            , 0x2F
            , 0x2A
            , 0xE8
            , 0xC3
            , 0x5A
            ]
        )
        ( B.pack
            [ 0xD4
            , 0x91
            , 0xDB
            , 0x16
            , 0xE7
            , 0xB1
            , 0xC3
            , 0x9E
            , 0x86
            , 0xCB
            , 0x08
            , 0x6B
            , 0x78
            , 0x9F
            , 0x54
            , 0x19
            ]
        )
        ( B.pack
            [ 0x01
            , 0x9F
            , 0x98
            , 0x09
            , 0xDE
            , 0x17
            , 0x11
            , 0x85
            , 0x8F
            , 0xAA
            , 0xC3
            , 0xA3
            , 0xBA
            , 0x20
            , 0xFB
            , 0xC3
            ]
        )
    ]

vectors_twofish192 =
    [ KAT_ECB
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xAB
            , 0xCD
            , 0xEF
            , 0xFE
            , 0xDC
            , 0xBA
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
            [ 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            ]
        )
        ( B.pack
            [ 0xCF
            , 0xD1
            , 0xD2
            , 0xE5
            , 0xA9
            , 0xBE
            , 0x9C
            , 0xDF
            , 0x50
            , 0x1F
            , 0x13
            , 0xB8
            , 0x92
            , 0xBD
            , 0x22
            , 0x48
            ]
        )
    , KAT_ECB
        ( B.pack
            [ 0x88
            , 0xB2
            , 0xB2
            , 0x70
            , 0x6B
            , 0x10
            , 0x5E
            , 0x36
            , 0xB4
            , 0x46
            , 0xBB
            , 0x6D
            , 0x73
            , 0x1A
            , 0x1E
            , 0x88
            , 0xEF
            , 0xA7
            , 0x1F
            , 0x78
            , 0x89
            , 0x65
            , 0xBD
            , 0x44
            ]
        )
        ( B.pack
            [ 0x39
            , 0xDA
            , 0x69
            , 0xD6
            , 0xBA
            , 0x49
            , 0x97
            , 0xD5
            , 0x85
            , 0xB6
            , 0xDC
            , 0x07
            , 0x3C
            , 0xA3
            , 0x41
            , 0xB2
            ]
        )
        ( B.pack
            [ 0x18
            , 0x2B
            , 0x02
            , 0xD8
            , 0x14
            , 0x97
            , 0xEA
            , 0x45
            , 0xF9
            , 0xDA
            , 0xAC
            , 0xDC
            , 0x29
            , 0x19
            , 0x3A
            , 0x65
            ]
        )
    ]

vectors_twofish256 =
    [ KAT_ECB
        ( B.pack
            [ 0x01
            , 0x23
            , 0x45
            , 0x67
            , 0x89
            , 0xAB
            , 0xCD
            , 0xEF
            , 0xFE
            , 0xDC
            , 0xBA
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
            , 0xAA
            , 0xBB
            , 0xCC
            , 0xDD
            , 0xEE
            , 0xFF
            ]
        )
        ( B.pack
            [ 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            , 0x00
            ]
        )
        ( B.pack
            [ 0x37
            , 0x52
            , 0x7B
            , 0xE0
            , 0x05
            , 0x23
            , 0x34
            , 0xB8
            , 0x9F
            , 0x0C
            , 0xFC
            , 0xCA
            , 0xE8
            , 0x7C
            , 0xFA
            , 0x20
            ]
        )
    , KAT_ECB
        ( B.pack
            [ 0xD4
            , 0x3B
            , 0xB7
            , 0x55
            , 0x6E
            , 0xA3
            , 0x2E
            , 0x46
            , 0xF2
            , 0xA2
            , 0x82
            , 0xB7
            , 0xD4
            , 0x5B
            , 0x4E
            , 0x0D
            , 0x57
            , 0xFF
            , 0x73
            , 0x9D
            , 0x4D
            , 0xC9
            , 0x2C
            , 0x1B
            , 0xD7
            , 0xFC
            , 0x01
            , 0x70
            , 0x0C
            , 0xC8
            , 0x21
            , 0x6F
            ]
        )
        ( B.pack
            [ 0x90
            , 0xAF
            , 0xE9
            , 0x1B
            , 0xB2
            , 0x88
            , 0x54
            , 0x4F
            , 0x2C
            , 0x32
            , 0xDC
            , 0x23
            , 0x9B
            , 0x26
            , 0x35
            , 0xE6
            ]
        )
        ( B.pack
            [ 0x6C
            , 0xB4
            , 0x56
            , 0x1C
            , 0x40
            , 0xBF
            , 0x0A
            , 0x97
            , 0x05
            , 0x93
            , 0x1C
            , 0xB6
            , 0xD4
            , 0x08
            , 0xE7
            , 0xFA
            ]
        )
    ]

kats128 = defaultKATs{kat_ECB = vectors_twofish128}
kats192 = defaultKATs{kat_ECB = vectors_twofish192}
kats256 = defaultKATs{kat_ECB = vectors_twofish256}

tests =
    testGroup
        "Twofish"
        [ testBlockCipher kats128 (undefined :: Twofish128)
        , testBlockCipher kats192 (undefined :: Twofish192)
        , testBlockCipher kats256 (undefined :: Twofish256)
        ]
