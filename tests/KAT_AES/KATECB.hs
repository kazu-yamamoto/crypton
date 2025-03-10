module KAT_AES.KATECB where

import qualified Data.ByteString as B

vectors_aes128_enc =
    [
        ( B.pack
            [ 0x10
            , 0xa5
            , 0x88
            , 0x69
            , 0xd7
            , 0x4b
            , 0xe5
            , 0xa3
            , 0x74
            , 0xcf
            , 0x86
            , 0x7c
            , 0xfb
            , 0x47
            , 0x38
            , 0x59
            ]
        , B.replicate 16 0
        , B.pack
            [ 0x6d
            , 0x25
            , 0x1e
            , 0x69
            , 0x44
            , 0xb0
            , 0x51
            , 0xe0
            , 0x4e
            , 0xaa
            , 0x6f
            , 0xb4
            , 0xdb
            , 0xf7
            , 0x84
            , 0x65
            ]
        )
    ,
        ( B.replicate 16 0
        , B.replicate 16 0
        , B.pack
            [ 0x66
            , 0xe9
            , 0x4b
            , 0xd4
            , 0xef
            , 0x8a
            , 0x2c
            , 0x3b
            , 0x88
            , 0x4c
            , 0xfa
            , 0x59
            , 0xca
            , 0x34
            , 0x2b
            , 0x2e
            ]
        )
    ,
        ( B.replicate 16 0
        , B.replicate 16 1
        , B.pack
            [ 0xe1
            , 0x4d
            , 0x5d
            , 0x0e
            , 0xe2
            , 0x77
            , 0x15
            , 0xdf
            , 0x08
            , 0xb4
            , 0x15
            , 0x2b
            , 0xa2
            , 0x3d
            , 0xa8
            , 0xe0
            ]
        )
    ,
        ( B.replicate 16 1
        , B.replicate 16 2
        , B.pack
            [ 0x17
            , 0xd6
            , 0x14
            , 0xf3
            , 0x79
            , 0xa9
            , 0x35
            , 0x90
            , 0x77
            , 0xe9
            , 0x55
            , 0x77
            , 0xfd
            , 0x31
            , 0xc2
            , 0x0a
            ]
        )
    ,
        ( B.replicate 16 2
        , B.replicate 16 1
        , B.pack
            [ 0x8f
            , 0x42
            , 0xc2
            , 0x4b
            , 0xee
            , 0x6e
            , 0x63
            , 0x47
            , 0x2b
            , 0x16
            , 0x5a
            , 0xa9
            , 0x41
            , 0x31
            , 0x2f
            , 0x7c
            ]
        )
    ,
        ( B.replicate 16 3
        , B.replicate 16 2
        , B.pack
            [ 0x90
            , 0x98
            , 0x85
            , 0xe4
            , 0x77
            , 0xbc
            , 0x20
            , 0xf5
            , 0x8a
            , 0x66
            , 0x97
            , 0x1d
            , 0xa0
            , 0xbc
            , 0x75
            , 0xe3
            ]
        )
    ]

vectors_aes192_enc =
    [
        ( B.replicate 24 0
        , B.replicate 16 0
        , B.pack
            [ 0xaa
            , 0xe0
            , 0x69
            , 0x92
            , 0xac
            , 0xbf
            , 0x52
            , 0xa3
            , 0xe8
            , 0xf4
            , 0xa9
            , 0x6e
            , 0xc9
            , 0x30
            , 0x0b
            , 0xd7
            ]
        )
    ,
        ( B.replicate 24 0
        , B.replicate 16 1
        , B.pack
            [ 0xcf
            , 0x1e
            , 0xce
            , 0x3c
            , 0x44
            , 0xb0
            , 0x78
            , 0xfb
            , 0x27
            , 0xcb
            , 0x0a
            , 0x3e
            , 0x07
            , 0x1b
            , 0x08
            , 0x20
            ]
        )
    ,
        ( B.replicate 24 1
        , B.replicate 16 2
        , B.pack
            [ 0xeb
            , 0x8c
            , 0x17
            , 0x30
            , 0x90
            , 0xc7
            , 0x5b
            , 0x77
            , 0xd6
            , 0x72
            , 0xb4
            , 0x57
            , 0xa7
            , 0x78
            , 0xd9
            , 0xd0
            ]
        )
    ,
        ( B.replicate 24 2
        , B.replicate 16 1
        , B.pack
            [ 0xf2
            , 0xf0
            , 0xae
            , 0xd8
            , 0xcd
            , 0xc9
            , 0x21
            , 0xca
            , 0x4b
            , 0x55
            , 0x84
            , 0x5d
            , 0xa4
            , 0x15
            , 0x21
            , 0xc2
            ]
        )
    ,
        ( B.replicate 24 3
        , B.replicate 16 2
        , B.pack
            [ 0xca
            , 0xcc
            , 0x30
            , 0x79
            , 0xe4
            , 0xb7
            , 0x95
            , 0x27
            , 0x63
            , 0xd2
            , 0x55
            , 0xd6
            , 0x34
            , 0x10
            , 0x46
            , 0x14
            ]
        )
    ]

vectors_aes256_enc =
    [
        ( B.replicate 32 0
        , B.replicate 16 0
        , B.pack
            [ 0xdc
            , 0x95
            , 0xc0
            , 0x78
            , 0xa2
            , 0x40
            , 0x89
            , 0x89
            , 0xad
            , 0x48
            , 0xa2
            , 0x14
            , 0x92
            , 0x84
            , 0x20
            , 0x87
            ]
        )
    ,
        ( B.replicate 32 0
        , B.replicate 16 1
        , B.pack
            [ 0x7b
            , 0xc3
            , 0x02
            , 0x6c
            , 0xd7
            , 0x37
            , 0x10
            , 0x3e
            , 0x62
            , 0x90
            , 0x2b
            , 0xcd
            , 0x18
            , 0xfb
            , 0x01
            , 0x63
            ]
        )
    ,
        ( B.replicate 32 1
        , B.replicate 16 2
        , B.pack
            [ 0x62
            , 0xae
            , 0x12
            , 0xf3
            , 0x24
            , 0xbf
            , 0xea
            , 0x08
            , 0xd5
            , 0xf6
            , 0x75
            , 0xb5
            , 0x13
            , 0x02
            , 0x6b
            , 0xbf
            ]
        )
    ,
        ( B.replicate 32 2
        , B.replicate 16 1
        , B.pack
            [ 0x00
            , 0xf9
            , 0xc7
            , 0x44
            , 0x4b
            , 0xb0
            , 0xcc
            , 0x80
            , 0x6c
            , 0x7c
            , 0x39
            , 0xee
            , 0x22
            , 0x11
            , 0xf1
            , 0x46
            ]
        )
    ,
        ( B.replicate 32 3
        , B.replicate 16 2
        , B.pack
            [ 0xb4
            , 0x05
            , 0x87
            , 0x3e
            , 0xa0
            , 0x76
            , 0x1b
            , 0x9c
            , 0xa9
            , 0x9f
            , 0x70
            , 0xb0
            , 0x16
            , 0x16
            , 0xce
            , 0xb1
            ]
        )
    ]

vectors_aes128_dec =
    [
        ( B.replicate 16 0
        , B.replicate 16 0
        , B.pack
            [ 0x14
            , 0x0f
            , 0x0f
            , 0x10
            , 0x11
            , 0xb5
            , 0x22
            , 0x3d
            , 0x79
            , 0x58
            , 0x77
            , 0x17
            , 0xff
            , 0xd9
            , 0xec
            , 0x3a
            ]
        )
    ,
        ( B.replicate 16 0
        , B.replicate 16 1
        , B.pack
            [ 0x15
            , 0x6d
            , 0x0f
            , 0x85
            , 0x75
            , 0xd5
            , 0x33
            , 0x07
            , 0x52
            , 0xf8
            , 0x4a
            , 0xf2
            , 0x72
            , 0xff
            , 0x30
            , 0x50
            ]
        )
    ,
        ( B.replicate 16 1
        , B.replicate 16 2
        , B.pack
            [ 0x34
            , 0x37
            , 0xd6
            , 0xe2
            , 0x31
            , 0xd7
            , 0x02
            , 0x41
            , 0x9b
            , 0x51
            , 0xb4
            , 0x94
            , 0x72
            , 0x71
            , 0xb6
            , 0x11
            ]
        )
    ,
        ( B.replicate 16 2
        , B.replicate 16 1
        , B.pack
            [ 0xe3
            , 0xcd
            , 0xe2
            , 0x37
            , 0xc8
            , 0xf2
            , 0xd9
            , 0x7b
            , 0x8d
            , 0x79
            , 0xf9
            , 0x17
            , 0x1d
            , 0x4b
            , 0xda
            , 0xc1
            ]
        )
    ,
        ( B.replicate 16 3
        , B.replicate 16 2
        , B.pack
            [ 0x5b
            , 0x94
            , 0xaa
            , 0xed
            , 0xd7
            , 0x83
            , 0x99
            , 0x8c
            , 0xd5
            , 0x15
            , 0x35
            , 0x35
            , 0x18
            , 0xcc
            , 0x45
            , 0xe2
            ]
        )
    ]

vectors_aes192_dec =
    [
        ( B.replicate 24 0
        , B.replicate 16 0
        , B.pack
            [ 0x13
            , 0x46
            , 0x0e
            , 0x87
            , 0xa8
            , 0xfc
            , 0x02
            , 0x3e
            , 0xf2
            , 0x50
            , 0x1a
            , 0xfe
            , 0x7f
            , 0xf5
            , 0x1c
            , 0x51
            ]
        )
    ,
        ( B.replicate 24 0
        , B.replicate 16 1
        , B.pack
            [ 0x92
            , 0x17
            , 0x07
            , 0xc3
            , 0x3d
            , 0x1c
            , 0xc5
            , 0x96
            , 0x7d
            , 0xa5
            , 0x1d
            , 0xbb
            , 0xb0
            , 0x66
            , 0xb2
            , 0x6c
            ]
        )
    ,
        ( B.replicate 24 1
        , B.replicate 16 2
        , B.pack
            [ 0xee
            , 0x92
            , 0x97
            , 0xc6
            , 0xba
            , 0xe8
            , 0x26
            , 0x4d
            , 0xff
            , 0x08
            , 0x0e
            , 0xbb
            , 0x1e
            , 0x74
            , 0x11
            , 0xc1
            ]
        )
    ,
        ( B.replicate 24 2
        , B.replicate 16 1
        , B.pack
            [ 0x49
            , 0x67
            , 0xdf
            , 0x70
            , 0xd2
            , 0x9e
            , 0x9a
            , 0x7f
            , 0x5d
            , 0x7c
            , 0xb9
            , 0xc1
            , 0x20
            , 0xc3
            , 0x8a
            , 0x71
            ]
        )
    ,
        ( B.replicate 24 3
        , B.replicate 16 2
        , B.pack
            [ 0x74
            , 0x38
            , 0x62
            , 0x42
            , 0x6b
            , 0x56
            , 0x7f
            , 0xd5
            , 0xf0
            , 0x1d
            , 0x1b
            , 0x59
            , 0x56
            , 0x01
            , 0x26
            , 0x29
            ]
        )
    ]

vectors_aes256_dec =
    [
        ( B.replicate 32 0
        , B.replicate 16 0
        , B.pack
            [ 0x67
            , 0x67
            , 0x1c
            , 0xe1
            , 0xfa
            , 0x91
            , 0xdd
            , 0xeb
            , 0x0f
            , 0x8f
            , 0xbb
            , 0xb3
            , 0x66
            , 0xb5
            , 0x31
            , 0xb4
            ]
        )
    ,
        ( B.replicate 32 0
        , B.replicate 16 1
        , B.pack
            [ 0xcc
            , 0x09
            , 0x21
            , 0xa3
            , 0xc5
            , 0xca
            , 0x17
            , 0xf7
            , 0x48
            , 0xb7
            , 0xc2
            , 0x7b
            , 0x73
            , 0xba
            , 0x87
            , 0xa2
            ]
        )
    ,
        ( B.replicate 32 1
        , B.replicate 16 2
        , B.pack
            [ 0xc0
            , 0x4b
            , 0x27
            , 0x90
            , 0x1a
            , 0x50
            , 0xcf
            , 0xfa
            , 0xf1
            , 0xbb
            , 0x88
            , 0x9f
            , 0xc0
            , 0x92
            , 0x5e
            , 0x14
            ]
        )
    ,
        ( B.replicate 32 2
        , B.replicate 16 1
        , B.pack
            [ 0x24
            , 0x61
            , 0x53
            , 0x5d
            , 0x16
            , 0x1c
            , 0x15
            , 0x39
            , 0x88
            , 0x32
            , 0x77
            , 0x29
            , 0xc5
            , 0x8c
            , 0xc0
            , 0x3a
            ]
        )
    ,
        ( B.replicate 32 3
        , B.replicate 16 2
        , B.pack
            [ 0x30
            , 0xc9
            , 0x1c
            , 0xce
            , 0xfe
            , 0x89
            , 0x30
            , 0xcf
            , 0xff
            , 0x31
            , 0xdb
            , 0xcc
            , 0xfc
            , 0x11
            , 0xc5
            , 0x23
            ]
        )
    ]
