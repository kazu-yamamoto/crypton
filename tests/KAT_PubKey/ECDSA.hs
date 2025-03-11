{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}

module KAT_PubKey.ECDSA (ecdsaTests) where

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.PubKey.ECC.ECDSA (
    PrivateKey (..),
    PublicKey (..),
    Signature (..),
    deterministicNonce,
    signWith,
    verify,
 )
import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Types
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Test.Tasty
import Test.Tasty.HUnit
import Text.Printf

-- existential type allows storing different hash algorithms in the same value
data HashAlg = forall hash. (Show hash, HashAlgorithm hash) => HashAlg hash
instance Show HashAlg where show (HashAlg alg) = show alg

data Entry = Entry
    { curveName :: CurveName
    , privateNumber :: PrivateNumber
    , publicPoint :: PublicPoint
    , hashAlgorithm :: HashAlg
    , message :: ByteString
    , nonce :: Integer
    , signature :: Signature
    }
instance Show Entry where
    show entry =
        printf
            "%s.%s.%s"
            (show $ curveName entry)
            (show $ B.take 8 $ message entry)
            (show $ hashAlgorithm entry)

normalize :: Entry -> Entry
normalize entry
    | s <= n `div` 2 = entry
    | otherwise = entry{signature = Signature r (n - s)}
  where
    Signature r s = signature entry
    n = ecc_n $ common_curve $ getCurveByName $ curveName entry

-- taken from GEC 2: Test Vectors for SEC 1
gec2Entries :: [Entry]
gec2Entries =
    [ Entry
        { curveName = SEC_p160r1
        , privateNumber = 971761939728640320549601132085879836204587084162
        , publicPoint =
            Point
                466448783855397898016055842232266600516272889280
                1110706324081757720403272427311003102474457754220
        , hashAlgorithm = HashAlg SHA1
        , message = "abc"
        , nonce = 702232148019446860144825009548118511996283736794
        , signature =
            Signature
                { sign_r = 1176954224688105769566774212902092897866168635793
                , sign_s = 299742580584132926933316745664091704165278518100
                }
        }
    , Entry
        { curveName = SEC_t163k1
        , privateNumber = 0x00000011f2626d90d26cb4c0379043b26e64107fc
        , publicPoint =
            Point
                0x0389fa5ad7f8304325a8c060ef7dcb83042c045bc
                0x0eefa094a5054da196943cc80509dcb9f59e5bc2e
        , hashAlgorithm = HashAlg SHA1
        , message =
            i2osp
                0xa2c1a03fdd00521bb08fc88d20344321977aaf637ef9d5470dd7d2c8628fc8d0d1f1d3587c6b3fd02386f8c13db341b14748a9475cc63baf065df64054b27d5c2cdf0f98e3bbb81d0b5dc94f8cdb87acf75720f6163de394c8c6af360bc1acb85b923a493b7b27cc111a257e36337bd94eb0fab9d5e633befb1ae7f1b244bfaa
        , nonce = 0x0000000c3a4ff97286126dab1e5089395fcc47ebb
        , signature =
            Signature
                { sign_r = 0x0dbe6c3a1dc851e7f2338b5c26c62b4b37bf8035c
                , sign_s = 0x1c76458135b1ff9fbd23009b8414a47996126b56a
                }
        }
    , Entry
        { curveName = SEC_t163k1
        , privateNumber = 0x00000006a3803301daee9af09bb5b6c991a4f49a4
        , publicPoint =
            Point
                0x4b500f555e857da8c299780130c5c3f48f02ee322
                0x5c1c0ae25b47f06cc46fb86b12d2d8c0ba6a4bf07
        , hashAlgorithm = HashAlg SHA1
        , message =
            i2osp
                0x67048080daaeb77d3ac31babdf8be23dbe75ceb4dfb94aa8113db5c5dcb6fe14b70f717b7b0ed0881835a66a86e6d840ffcb7d976c75ef2d1d4322fbbc86357384e24707aef88cea2c41a01a9a3d1b9e72ce650c7fdecc4f9448d3a77df6cdf13647ab295bb3132de0b1b2c402d8d2de7d452f1e003e0695de1470d1064eee16
        , nonce = 0x0000002f39fbf77f3e0dc046116de692b6cf91b16
        , signature =
            Signature
                { sign_r = 0x3d3eeda42f65d727f4a564f1415654356c6c57a6c
                , sign_s = 0x35e4d43c5f08baddf138449db1ad0b7872552b7cd
                }
        }
    , Entry
        { curveName = SEC_t163k1
        , privateNumber = 0x0000002e28676514bd93fea11b62db0f6e324b18d
        , publicPoint =
            Point
                0x3f9c90b71f6a1de20a2716f38ef1b5f98c757bd42
                0x2ff0a5d266d447ef62d43fbca6c34c08c1ce35a40
        , hashAlgorithm = HashAlg SHA1
        , message =
            i2osp
                0x77e007dc2acd7248256165a4b30e98986f51a81efd926b85f74c81bc2a6d2bcd030060a844091e22fbb0ff3db5a20caaefb5d58ccdcbc27f0ff8a4d940e78f303079ec1ca5b0ca3d4ecc7580f8b34a9f0496c9e719d2ec3e1614b7644bc11179e895d2c0b58a1da204fbf0f6e509f97f983eacb6487092caf6e8e4e6b3c458b2
        , nonce = 0x00000001233ae699883e74e7f4dfb5279ff22280a
        , signature =
            Signature
                { sign_r = 0x39de3cd2cf04145e522b8fba3f23e9218226e0860
                , sign_s = 0x2af62bfb3cfa202e2342606ee5bb0934c3b0375b6
                }
        }
    , Entry
        { curveName = SEC_t163k1
        , privateNumber = 0x000000361dd088e3a6d3c910686c8dce57e5d4d8e
        , publicPoint =
            Point
                0x064f905c1da9d7e9c32d81890ae6f30dcc7839d32
                0x06f1faedb6d9032016d3b681e7cf69c29d29eb27b
        , hashAlgorithm = HashAlg SHA1
        , message =
            i2osp
                0xfbacfcce4688748406ddf5c3495021eef8fb399865b649eb2395a04a1ab28335da2c236d306fcc59f7b65ea931cf0139571e1538ede5688958c3ac69f47a285362f5ad201f89cc735b7b465408c2c41b310fc8908d0be45054df2a7351fae36b390e842f3b5cdd9ad832940df5b2d25c2ed43ce86eaf2508bcf401ae58bb1d47
        , nonce = 0x00000022f723e9f5da56d3d0837d5dca2f937395f
        , signature =
            Signature
                { sign_r = 0x374cdc8571083fecfbd4e25e1cd69ecc66b715f2d
                , sign_s = 0x313b10949222929b2f20b15d446c27d6dcae3f086
                }
        }
    ]

data EntryCurve = EntryCurve
    { ecName :: CurveName
    , ecPrivate :: PrivateNumber
    , ecPublic :: PublicPoint
    , ecMessages :: [EntryMessage]
    }
data EntryMessage = EntryMessage
    { emMessage :: ByteString
    , emHashes :: [EntryHash]
    }
data EntryHash = EntryHash
    { ehAlgorithm :: HashAlg
    , ehK :: Integer
    , ehR :: Integer
    , ehS :: Integer
    }

flatten :: [EntryCurve] -> [Entry]
flatten hierarchy = do
    entryCurve <- hierarchy
    entryMessage <- ecMessages entryCurve
    entryHash <- emHashes entryMessage
    pure $
        Entry
            { curveName = ecName entryCurve
            , privateNumber = ecPrivate entryCurve
            , publicPoint = ecPublic entryCurve
            , hashAlgorithm = ehAlgorithm entryHash
            , message = emMessage entryMessage
            , nonce = ehK entryHash
            , signature = Signature (ehR entryHash) (ehS entryHash)
            }

-- taken from RFC 6979
rfc6979Entries :: [EntryCurve]
rfc6979Entries =
    [ EntryCurve
        { ecName = SEC_p192r1
        , ecPrivate = 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4
        , ecPublic =
            Point
                0xAC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56
                0x3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021
                        , ehR = 0x98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF
                        , ehS = 0x57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x4381526B3FC1E7128F202E194505592F01D5FF4C5AF015D8
                        , ehR = 0xA1F00DAD97AEEC91C95585F36200C65F3C01812AA60378F5
                        , ehS = 0xE07EC1304C7C6C9DEBBE980B9692668F81D4DE7922A0F97A
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496
                        , ehR = 0x4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55
                        , ehS = 0xCCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x4730005C4FCB01834C063A7B6760096DBE284B8252EF4311
                        , ehR = 0xDA63BF0B9ABCF948FBB1E9167F136145F7A20426DCC287D5
                        , ehS = 0xC3AA2C960972BD7A2003A57E1C4C77F0578F8AE95E31EC5E
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0xA2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1
                        , ehR = 0x4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8
                        , ehS = 0x3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0xD9CF9C3D3297D3260773A1DA7418DB5537AB8DD93DE7FA25
                        , ehR = 0x0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D
                        , ehS = 0xEB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0xF5DC805F76EF851800700CCE82E7B98D8911B7D510059FBE
                        , ehR = 0x6945A1C1D1B2206B8145548F633BB61CEF04891BAF26ED34
                        , ehS = 0xB7FB7FDFC339C0B9BD61A9F5A8EAF9BE58FC5CBA2CB15293
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6C
                        , ehR = 0x3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE
                        , ehS = 0x5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x5AFEFB5D3393261B828DB6C91FBC68C230727B030C975693
                        , ehR = 0xB234B60B4DB75A733E19280A7A6034BD6B1EE88AF5332367
                        , ehS = 0x7994090B2D59BB782BE57E74A44C9A1C700413F8ABEFE77A
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x0758753A5254759C7CFBAD2E2D9B0792EEE44136C9480527
                        , ehR = 0xFE4F4AE86A58B6507946715934FE2D8FF9D95B6B098FE739
                        , ehS = 0x74CF5605C98FBA0E1EF34D4B5A1577A7DCF59457CAE52290
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_p224r1
        , ecPrivate = 0xF220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1
        , ecPublic =
            Point
                0x00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C
                0xEEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x7EEFADD91110D8DE6C2C470831387C50D3357F7F4D477054B8B426BC
                        , ehR = 0x22226F9D40A96E19C4A301CE5B74B115303C0F3A4FD30FC257FB57AC
                        , ehS = 0x66D1CDD83E3AF75605DD6E2FEFF196D30AA7ED7A2EDF7AF475403D69
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0xC1D1F2F10881088301880506805FEB4825FE09ACB6816C36991AA06D
                        , ehR = 0x1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E
                        , ehS = 0xA6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0xAD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC
                        , ehR = 0x61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA
                        , ehS = 0xBC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x52B40F5A9D3D13040F494E83D3906C6079F29981035C7BD51E5CAC40
                        , ehR = 0x0B115E5E36F0F9EC81F1325A5952878D745E19D7BB3EABFABA77E953
                        , ehS = 0x830F34CCDFE826CCFDC81EB4129772E20E122348A2BBD889A1B1AF1D
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x9DB103FFEDEDF9CFDBA05184F925400C1653B8501BAB89CEA0FBEC14
                        , ehR = 0x074BD1D979D5F32BF958DDC61E4FB4872ADCAFEB2256497CDAC30397
                        , ehS = 0xA4CECA196C3D5A1FF31027B33185DC8EE43F288B21AB342E5D8EB084
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x2519178F82C3F0E4F87ED5883A4E114E5B7A6E374043D8EFD329C253
                        , ehR = 0xDEAA646EC2AF2EA8AD53ED66B2E2DDAA49A12EFD8356561451F3E21C
                        , ehS = 0x95987796F6CF2062AB8135271DE56AE55366C045F6D9593F53787BD2
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0xDF8B38D40DCA3E077D0AC520BF56B6D565134D9B5F2EAE0D34900524
                        , ehR = 0xC441CE8E261DED634E4CF84910E4C5D1D22C5CF3B732BB204DBEF019
                        , ehS = 0x902F42847A63BDC5F6046ADA114953120F99442D76510150F372A3F4
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0xFF86F57924DA248D6E44E8154EB69F0AE2AEBAEE9931D0B5A969F904
                        , ehR = 0xAD04DDE87B84747A243A631EA47A1BA6D1FAA059149AD2440DE6FBA6
                        , ehS = 0x178D49B1AE90E3D8B629BE3DB5683915F4E8C99FDF6E666CF37ADCFD
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x7046742B839478C1B5BD31DB2E862AD868E1A45C863585B5F22BDC2D
                        , ehR = 0x389B92682E399B26518A95506B52C03BC9379A9DADF3391A21FB0EA4
                        , ehS = 0x414A718ED3249FF6DBC5B50C27F71F01F070944DA22AB1F78F559AAB
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0xE39C2AA4EA6BE2306C72126D40ED77BF9739BB4D6EF2BBB1DCB6169D
                        , ehR = 0x049F050477C5ADD858CAC56208394B5A55BAEBBE887FDF765047C17C
                        , ehS = 0x077EB13E7005929CEFA3CD0403C7CDCC077ADF4E44F3C41B2F60ECFF
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_p256r1
        , ecPrivate = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        , ecPublic =
            Point
                0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
                0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
                        , ehR = 0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32
                        , ehS = 0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473
                        , ehR = 0x53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F
                        , ehS = 0xB9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
                        , ehR = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
                        , ehS = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4
                        , ehR = 0x0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719
                        , ehS = 0x4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
                        , ehR = 0x8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00
                        , ehS = 0x2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2E
                        , ehR = 0x0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89
                        , ehS = 0x01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7
                        , ehR = 0xC37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692
                        , ehS = 0xC820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
                        , ehR = 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
                        , ehS = 0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8
                        , ehR = 0x83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6
                        , ehS = 0x8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F
                        , ehR = 0x461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04
                        , ehS = 0x39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_p384r1
        , ecPrivate =
            0x6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5
        , ecPublic =
            Point
                0xEC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13
                0x8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x4471EF7518BB2C7C20F62EAE1C387AD0C5E8E470995DB4ACF694466E6AB096630F29E5938D25106C3C340045A2DB01A7
                        , ehR =
                            0xEC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA37B9BA002899F6FDA3A4A9386790D4EB2
                        , ehS =
                            0xA3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF26F49CA031D4857570CCB5CA4424A443
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0xA4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB8083EE4E3C45B06A5899EA56C51B5879
                        , ehR =
                            0x42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366450F76EE3DE43F5A125333A6BE060122
                        , ehS =
                            0x9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E4834C082C03D83028EFBF93A3C23940CA8D
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C899F9F2EDF9747A9B60
                        , ehR =
                            0x21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD
                        , ehS =
                            0xF3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA95368623B8C4686915CF9
                        , ehR =
                            0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46
                        , ehS =
                            0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331A4E966532593A52980D0E3AAA5E10EC3
                        , ehR =
                            0xED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709
                        , ehS =
                            0x512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x66CC2C8F4D303FC962E5FF6A27BD79F84EC812DDAE58CF5243B64A4AD8094D47EC3727F3A3C186C15054492E30698497
                        , ehR =
                            0x4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F7789A8B8E43D0678ACD9D29876DAF46638645F7F404B11C7
                        , ehS =
                            0xD5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8C4B7186201A2991695BA1C84541327E966FA7B50F7382282
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x18FA39DB95AA5F561F30FA3591DC59C0FA3653A80DAFFA0B48D1A4C6DFCBFF6E3D33BE4DC5EB8886A8ECD093F2935726
                        , ehR =
                            0xE8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE888FC5BF954B5E62464A9A817C47FF78B8C11066B24080E72
                        , ehS =
                            0x07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3286B2BD43FA8C6141C53EA5ABEF0D8231077A04540A96B66
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FAA48DD070BA79921A3457ABFF2D630AD7
                        , ehR =
                            0x6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B
                        , ehS =
                            0x2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092ADA71F4A459BC0DA98ADB95837DB8312EA
                        , ehR =
                            0x8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB
                        , ehS =
                            0xDDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE0E2CC8A136036DC4B9C00E6888F66B6C
                        , ehR =
                            0xA0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277
                        , ehS =
                            0x976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_p521r1
        , ecPrivate =
            0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538
        , ecPublic =
            Point
                0x1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4
                0x0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x089C071B419E1C2820962321787258469511958E80582E95D8378E0C2CCDB3CB42BEDE42F50E3FA3C71F5A76724281D31D9C89F0F91FC1BE4918DB1C03A5838D0F9
                        , ehR =
                            0x0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D
                        , ehS =
                            0x0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x121415EC2CD7726330A61F7F3FA5DE14BE9436019C4DB8CB4041F3B54CF31BE0493EE3F427FB906393D895A19C9523F3A1D54BB8702BD4AA9C99DAB2597B92113F3
                        , ehR =
                            0x1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A30715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2ED2E
                        , ehS =
                            0x050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17BA41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B41F
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C32575761793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0
                        , ehR =
                            0x1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7
                        , ehS =
                            0x04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x1546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FFAD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4211
                        , ehR =
                            0x1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451
                        , ehS =
                            0x1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3
                        , ehR =
                            0x0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA
                        , ehS =
                            0x0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x0BB9F2BF4FE1038CCF4DABD7139A56F6FD8BB1386561BD3C6A4FC818B20DF5DDBA80795A947107A1AB9D12DAA615B1ADE4F7A9DC05E8E6311150F47F5C57CE8B222
                        , ehR =
                            0x13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0367
                        , ehS =
                            0x1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC916797FF
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x040D09FCF3C8A5F62CF4FB223CBBB2B9937F6B0577C27020A99602C25A01136987E452988781484EDBBCF1C47E554E7FC901BC3085E5206D9F619CFF07E73D6F706
                        , ehR =
                            0x1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE17FB
                        , ehS =
                            0x177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD519A4
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E843841AF09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909258
                        , ehR =
                            0x00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8
                        , ehS =
                            0x0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x1F1FC4A349A7DA9A9E116BFDD055DC08E78252FF8E23AC276AC88B1770AE0B5DCEB1ED14A4916B769A523CE1E90BA22846AF11DF8B300C38818F713DADD85DE0C88
                        , ehR =
                            0x14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C
                        , ehS =
                            0x133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x16200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC56D
                        , ehR =
                            0x13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D
                        , ehS =
                            0x1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t163k1
        , ecPrivate = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
        , ecPublic =
            Point
                0x79AEE090DB05EC252D5CB4452F356BE198A4FF96F
                0x782E29634DDC9A31EF40386E896BAA18B53AFA5A3
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x09744429FA741D12DE2BE8316E35E84DB9E5DF1CD
                        , ehR = 0x30C45B80BA0E1406C4EFBBB7000D6DE4FA465D505
                        , ehS = 0x38D87DF89493522FC4CD7DE1553BD9DBBA2123011
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x323E7B28BFD64E6082F5B12110AA87BC0D6A6E159
                        , ehR = 0x38A2749F7EA13BD5DA0C76C842F512D5A65FFAF32
                        , ehS = 0x064F841F70112B793FD773F5606BFA5AC2A04C1E8
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B
                        , ehR = 0x113A63990598A3828C407C0F4D2438D990DF99A7F
                        , ehS = 0x1313A2E03F5412DDB296A22E2C455335545672D9F
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x2132ABE0ED518487D3E4FA7FD24F8BED1F29CCFCE
                        , ehR = 0x34D4DE955871BB84FEA4E7D068BA5E9A11BD8B6C4
                        , ehS = 0x2BAAF4D4FD57F175C405A2F39F9755D9045C820BD
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x00BBCC2F39939388FDFE841892537EC7B1FF33AA3
                        , ehR = 0x38E487F218D696A7323B891F0CCF055D895B77ADC
                        , ehS = 0x0972D7721093F9B3835A5EB7F0442FA8DCAA873C4
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x14CAB9192F39C8A0EA8E81B4B87574228C99CD681
                        , ehR = 0x1375BEF93F21582F601497036A7DC8014A99C2B79
                        , ehS = 0x254B7F1472FFFEE9002D081BB8CE819CCE6E687F9
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x091DD986F38EB936BE053DD6ACE3419D2642ADE8D
                        , ehR = 0x110F17EF209957214E35E8C2E83CBE73B3BFDEE2C
                        , ehS = 0x057D5022392D359851B95DEC2444012502A5349CB
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x193649CE51F0CFF0784CFC47628F4FA854A93F7A2
                        , ehR = 0x0354D5CD24F9C41F85D02E856FA2B0001C83AF53E
                        , ehS = 0x020B200677731CD4FE48612A92F72A19853A82B65
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x37C73C6F8B404EC83DA17A6EBCA724B3FF1F7EEBA
                        , ehR = 0x11B6A84206515495AD8DBB2E5785D6D018D75817E
                        , ehS = 0x1A7D4C1E17D4030A5D748ADEA785C77A54581F6D0
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x331AD98D3186F73967B1E0B120C80B1E22EFC2988
                        , ehR = 0x148934745B351F6367FF5BB56B1848A2F508902A9
                        , ehS = 0x36214B19444FAB504DBA61D4D6FF2D2F9640F4837
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t233k1
        , ecPrivate = 0x103B2142BDC2A3C3B55080D09DF1808F79336DA2399F5CA7171D1BE9B0
        , ecPublic =
            Point
                0x0682886F36C68473C1A221720C2B12B9BE13458BA907E1C4736595779F2
                0x1B20639B41BE0927090999B7817A3B3928D20503A39546044EC13A10309
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x273179E3E12C69591AD3DD9C7CCE3985820E3913AB6696EB14486DDBCF
                        , ehR = 0x5474541C988A9A1F73899F55EF28963DFFBBF0C2B1A1EE787C6A76C6A4
                        , ehS = 0x46301F9EC6624257BFC70D72186F17898EDBD0A3522560A88DD1B7D45A
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x71626A309D9CD80AD0B975D757FE6BF4B84E49F8F34C780070D7746F19
                        , ehR = 0x667F2FCE3E1C497EBD8E4B7C6372A8234003FE4ED6D4515814E7E11430
                        , ehS = 0x6A1C41340DAA730320DB9475F10E29A127D7AE3432F155E1F7954E1B57
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x73552F9CAC5774F74F485FA253871F2109A0C86040552EAA67DBA92DC9
                        , ehR = 0x38AD9C1D2CB29906E7D63C24601AC55736B438FB14F4093D6C32F63A10
                        , ehS = 0x647AAD2599C21B6EE89BE7FF957D98F684B7921DE1FD3CC82C079624F4
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x17D726A67539C609BD99E29AA3737EF247724B71455C3B6310034038C8
                        , ehR = 0x0C6510F57559C36FBCFF8C7BA4B81853DC618AD0BAAB03CFFDF3FD09FD
                        , ehS = 0x0AD331EE1C9B91A88BA77997235769C60AD07EE69E11F7137E17C5CF67
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x0E535C328774CDE546BE3AF5D7FCD263872F107E807435105BA2FDC166
                        , ehR = 0x47C4AC1B344028CC740BA7BB9F8AA59D6390E3158153D4F2ADE4B74950
                        , ehS = 0x26CE0CDE18A1B884B3EE1A879C13B42F11BB7C85F7A3745C8BECEC8E6E
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x1D8BBF5CB6EFFA270A1CDC22C81E269F0CC16E27151E0A460BA9B51AFF
                        , ehR = 0x4780B2DE4BAA5613872179AD90664249842E8B96FCD5653B55DD63EED4
                        , ehS = 0x6AF46BA322E21D4A88DAEC1650EF38774231276266D6A45ED6A64ECB44
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x67634D0ABA2C9BF7AE54846F26DCD166E7100654BCE6FDC96667631AA2
                        , ehR = 0x61D9CC8C842DF19B3D9F4BDA0D0E14A957357ADABC239444610FB39AEA
                        , ehS = 0x66432278891CB594BA8D08A0C556053D15917E53449E03C2EF88474CF6
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x2CE5AEDC155ACC0DDC5E679EBACFD21308362E5EFC05C5E99B2557A8D7
                        , ehR = 0x05E4E6B4DB0E13034E7F1F2E5DBAB766D37C15AE4056C7EE607C8AC7F4
                        , ehS = 0x5FC46AA489BF828B34FBAD25EC432190F161BEA8F60D3FCADB0EE3B725
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x1B4BD3903E74FD0B31E23F956C70062014DFEFEE21832032EA5352A055
                        , ehR = 0x50F1EFEDFFEC1088024620280EE0D7641542E4D4B5D61DB32358FC571B
                        , ehS = 0x4614EAE449927A9EB2FCC42EA3E955B43D194087719511A007EC9217A5
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x1775ED919CA491B5B014C5D5E86AF53578B5A7976378F192AF665CB705
                        , ehR = 0x6FE6D0D3A953BB66BB01BC6B9EDFAD9F35E88277E5768D1B214395320F
                        , ehS = 0x7C01A236E4BFF0A771050AD01EC1D24025D3130BBD9E4E81978EB3EC09
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t283k1
        , ecPrivate =
            0x06A0777356E87B89BA1ED3A3D845357BE332173C8F7A65BDC7DB4FAB3C4CC79ACC8194E
        , ecPublic =
            Point
                0x25330D0A651D5A20DC6389BC02345117725640AEC3C126612CE444EDD19649BDECC03D6
                0x505BD60A4B67182474EC4D1C668A73140F70504A68F39EFCD972487E9530E0508A76193
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x0A96F788DECAF6C9DBE24DC75ABA6EAAE85E7AB003C8D4F83CB1540625B2993BF445692
                        , ehR = 0x1B66D1E33FBDB6E107A69B610995C93C744CEBAEAF623CB42737C27D60188BD1D045A68
                        , ehS = 0x02E45B62C9C258643532FD536594B46C63B063946494F95DAFF8759FD552502324295C5
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x1B4C4E3B2F6B08B5991BD2BDDE277A7016DA527AD0AAE5BC61B64C5A0EE63E8B502EF61
                        , ehR = 0x018CF2F371BE86BB62E02B27CDE56DDAC83CCFBB3141FC59AEE022B66AC1A60DBBD8B76
                        , ehS = 0x1854E02A381295EA7F184CEE71AB7222D6974522D3B99B309B1A8025EB84118A28BF20E
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x1CEB9E8E0DFF53CE687DEB81339ACA3C98E7A657D5A9499EF779F887A934408ECBE5A38
                        , ehR = 0x19E90AA3DE5FB20AED22879F92C6FED278D9C9B9293CC5E94922CD952C9DBF20DF1753A
                        , ehS = 0x135AA7443B6A25D11BB64AC482E04D47902D017752882BD72527114F46CF8BB56C5A8C3
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x1460A5C41745A5763A9D548AE62F2C3630BBED71B6AA549D7F829C22442A728C5D965DA
                        , ehR = 0x0F8C1CA9C221AD9907A136F787D33BA56B0495A40E86E671C940FD767EDD75EB6001A49
                        , ehS = 0x1071A56915DEE89E22E511975AA09D00CDC4AA7F5054CBE83F5977EE6F8E1CC31EC43FD
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x00F3B59FCB5C1A01A1A2A0019E98C244DFF61502D6E6B9C4E957EDDCEB258EF4DBEF04A
                        , ehR = 0x1D0008CF4BA4A701BEF70771934C2A4A87386155A2354140E2ED52E18553C35B47D9E50
                        , ehS = 0x0D15F4FA1B7A4D41D9843578E22EF98773179103DC4FF0DD1F74A6B5642841B91056F78
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x168B5F8C0881D4026C08AC5894A2239D219FA9F4DA0600ADAA56D5A1781AF81F08A726E
                        , ehR = 0x140932FA7307666A8CCB1E1A09656CC40F5932965841ABD5E8E43559D93CF2311B02767
                        , ehS = 0x16A2FD46DA497E5E739DED67F426308C45C2E16528BF2A17EB5D65964FD88B770FBB9C6
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x045E13EA645CE01D9B25EA38C8A8A170E04C83BB7F231EE3152209FE10EC8B2E565536C
                        , ehR = 0x0E72AF7E39CD72EF21E61964D87C838F977485FA6A7E999000AFA97A381B2445FCEE541
                        , ehS = 0x1644FF7D848DA1A040F77515082C27C763B1B4BF332BCF5D08251C6B57D806319778208
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x0B585A7A68F51089691D6EDE2B43FC4451F66C10E65F134B963D4CBD4EB844B0E1469A6
                        , ehR = 0x158FAEB2470B306C57764AFC8528174589008449E11DB8B36994B607A65956A59715531
                        , ehS = 0x0521BC667CA1CA42B5649E78A3D76823C678B7BB3CD58D2E93CD791D53043A6F83F1FD1
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x1E88738E14482A09EE16A73D490A7FE8739DF500039538D5C4B6C8D6D7F208D6CA56760
                        , ehR = 0x1CC4DC5479E0F34C4339631A45AA690580060BF0EB518184C983E0E618C3B93AAB14BBE
                        , ehS = 0x0284D72FF8AFA83DE364502CBA0494BB06D40AE08F9D9746E747EA87240E589BA0683B7
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x00E5F24A223BD459653F682763C3BB322D4EE75DD89C63D4DC61518D543E76585076BBA
                        , ehR = 0x1E7912517C6899732E09756B1660F6B96635D638283DF9A8A11D30E008895D7F5C9C7F3
                        , ehS = 0x0887E75CBD0B7DD9DE30ED79BDB3D78E4F1121C5EAFF5946918F594F88D363644789DA7
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t409k1
        , ecPrivate =
            0x29C16768F01D1B8A89FDA85E2EFD73A09558B92A178A2931F359E4D70AD853E569CDAF16DAA569758FB4E73089E4525D8BBFCF
        , ecPublic =
            Point
                0x0CF923F523FE34A6E863D8BA45FB1FE6D784C8F219C414EEF4DB8362DBBD3CA71AEB28F568668D5D7A0093E2B84F6FAD759DB42
                0x13B1C374D5132978A1B1123EBBE9A5C54D1A9D56B09AFDB4ADE93CCD7C4D332E2916F7D4B9D18578EE3C2E2DE4D2ECE0DE63549
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x7866E5247F9A3556F983C86E81EDA696AC8489DB40A2862F278603982D304F08B2B6E1E7848534BEAF1330D37A1CF84C7994C1
                        , ehR =
                            0x7192EE99EC7AFE23E02CB1F9850D1ECE620475EDA6B65D04984029408EC1E5A6476BC940D81F218FC31D979814CAC6E78340FA
                        , ehS =
                            0x1DE75DE97CBE740FC79A6B5B22BC2B7832C687E6960F0B8173D5D8BE2A75AC6CA43438BAF69C669CE6D64E0FB93BC5854E0F81
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x512340DB682C7B8EBE407BF1AA54194DFE85D49025FE0F632C9B8A06A996F2FCD0D73C752FB09D23DB8FBE50605DC25DF0745C
                        , ehR =
                            0x41C8EDF39D5E4E76A04D24E6BFD4B2EC35F99CD2483478FD8B0A03E99379576EDACC4167590B7D9C387857A5130B1220CB771F
                        , ehS =
                            0x659652EEAC9747BCAD58034B25362B6AA61836E1BA50E2F37630813050D43457E62EAB0F13AE197E6CFE0244F983107555E269
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x782385F18BAF5A36A588637A76DFAB05739A14163BF723A4417B74BD1469D37AC9E8CCE6AEC8FF63F37B815AAF14A876EED962
                        , ehR =
                            0x49EC220D6D24980693E6D33B191532EAB4C5D924E97E305E2C1CCFE6F1EAEF96C17F6EC27D1E06191023615368628A7E0BD6A9
                        , ehS =
                            0x1A4AB1DD9BAAA21F77C503E1B39E770FFD44718349D54BA4CF08F688CE89D7D7C5F7213F225944BE5F7C9BA42B8BEE382F8AF9
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x4DA637CB2E5C90E486744E45A73935DD698D4597E736DA332A06EDA8B26D5ABC6153EC2ECE14981CF3E5E023F36FFA55EEA6D7
                        , ehR =
                            0x562BB99EE027644EC04E493C5E81B41F261F6BD18FB2FAE3AFEAD91FAB8DD44AFA910B13B9C79C87555225219E44E72245BB7C
                        , ehS =
                            0x25BA5F28047DDDBDA7ED7E49DA31B62B20FD9C7E5B8988817BBF738B3F4DFDD2DCD06EE6DF2A1B744C850DAF952C12B9A56774
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x57055B293ECFDFE983CEF716166091E573275C53906A39EADC25C89C5EC8D7A7E5629FCFDFAD514E1348161C9A34EA1C42D58C
                        , ehR =
                            0x16C7E7FB33B5577F7CF6F77762F0F2D531C6E7A3528BD2CF582498C1A48F200789E9DF7B754029DA0D7E3CE96A2DC760932606
                        , ehS =
                            0x2729617EFBF80DA5D2F201AC7910D3404A992C39921C2F65F8CF4601392DFE933E6457EAFDBD13DFE160D243100378B55C290A
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x545453D8DC05D220F9A12EF322D0B855E664C72835FABE8A41211453EB8A7CFF950D80773839D0043A46852DDA5A536E02291F
                        , ehR =
                            0x565648A5BAD24E747A7D7531FA9DBDFCB184ECFEFDB00A319459242B68D0989E52BED4107AED35C27D8ECA10E876ACA48006C9
                        , ehS =
                            0x7420BA6FF72ECC5C92B7CA0309258B5879F26393DB22753B9EC5DF905500A04228AC08880C485E2AC8834E13E8FA44FA57BF18
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x3C5352929D4EBE3CCE87A2DCE380F0D2B33C901E61ABC530DAF3506544AB0930AB9BFD553E51FCDA44F06CD2F49E17E07DB519
                        , ehR =
                            0x251DFE54EAEC8A781ADF8A623F7F36B4ABFC7EE0AE78C8406E93B5C3932A8120AB8DFC49D8E243C7C30CB5B1E021BADBDF9CA4
                        , ehS =
                            0x77854C2E72EAA6924CC0B5F6751379D132569843B1C7885978DBBAA6678967F643A50DBB06E6EA6102FFAB7766A57C3887BD22
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x251E32DEE10ED5EA4AD7370DF3EFF091E467D5531CA59DE3AA791763715E1169AB5E18C2A11CD473B0044FB45308E8542F2EB0
                        , ehR =
                            0x58075FF7E8D36844EED0FC3F78B7CFFDEEF6ADE5982D5636552A081923E24841C9E37DF2C8C4BF2F2F7A174927F3B7E6A0BEB2
                        , ehS =
                            0x0A737469D013A31B91E781CE201100FDE1FA488ABF2252C025C678462D715AD3078C9D049E06555CABDF37878CFB909553FF51
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x11C540EA46C5038FE28BB66E2E9E9A04C9FE9567ADF33D56745953D44C1DC8B5B92922F53A174E431C0ED8267D919329F19014
                        , ehR =
                            0x1C5C88642EA216682244E46E24B7CE9AAEF9B3F97E585577D158C3CBC3C598250A53F6D46DFB1E2DD9DC302E7DA4F0CAAFF291
                        , ehS =
                            0x1D3FD721C35872C74514359F88AD983E170E5DE5B31AFC0BE12E9F4AB2B2538C7797686BA955C1D042FD1F8CDC482775579F11
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x59527CE953BC09DF5E85155CAE7BB1D7F342265F41635545B06044F844ECB4FA6476E7D47420ADC8041E75460EC0A4EC760E95
                        , ehR =
                            0x1A32CD7764149DF79349DBF79451F4585BB490BD63A200700D7111B45DDA414000AE1B0A69AEACBA1364DD7719968AAD123F93
                        , ehS =
                            0x582AB1076CAFAE23A76244B82341AEFC4C6D8D8060A62A352C33187720C8A37F3DAC227E62758B11DF1562FD249941C1679F82
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t571k1
        , ecPrivate =
            0x0C16F58550D824ED7B95569D4445375D3A490BC7E0194C41A39DEB732C29396CDF1D66DE02DD1460A816606F3BEC0F32202C7BD18A32D87506466AA92032F1314ED7B19762B0D22
        , ecPublic =
            Point
                0x6CFB0DF7541CDD4C41EF319EA88E849EFC8605D97779148082EC991C463ED32319596F9FDF4779C17CAF20EFD9BEB57E9F4ED55BFC52A2FA15CA23BC62B7BF019DB59793DD77318
                0x1CFC91102F7759A561BD8D5B51AAAEEC7F40E659D67870361990D6DE29F6B4F7E18AE13BDE5EA5C1F77B23D676F44050C9DBFCCDD7B3756328DDA059779AAE8446FC5158A75C227
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x17F7E360B21BEAE4A757A19ACA77FB404D273F05719A86EAD9D7B3F4D5ED7B4630584BB153CF7DCD5A87CCA101BD7EA9ECA0CE5EE27CA985833560000BB52B6BBE068740A45B267
                        , ehR =
                            0x0767913F96C82E38B7146A505938B79EC07E9AA3214377651BE968B52C039D3E4837B4A2DE26C481C4E1DE96F4D9DE63845D9B32E26D0D332725678E3CE57F668A5E3108FB6CEA5
                        , ehS =
                            0x109F89F55FA39FF465E40EBCF869A9B1DB425AEA53AB4ECBCE3C310572F79315F5D4891461372A0C36E63871BEDDBB3BA2042C6410B67311F1A185589FF4C987DBA02F9D992B9DF
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x0B599D068A1A00498EE0B9AD6F388521F594BD3F234E47F7A1DB6490D7B57D60B0101B36F39CC22885F78641C69411279706F0989E6991E5D5B53619E43EFB397E25E0814EF02BC
                        , ehR =
                            0x010774B9F14DE6C9525131AD61531FA30987170D43782E9FB84FF0D70F093946DF75ECB69D400FE39B12D58C67C19DCE96335CEC1D9AADE004FE5B498AB8A940D46C8444348686A
                        , ehS =
                            0x06DFE9AA5FEA6CF2CEDC06EE1F9FD9853D411F0B958F1C9C519C90A85F6D24C1C3435B3CDF4E207B4A67467C87B7543F6C0948DD382D24D1E48B3763EC27D4D32A0151C240CC5E0
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x0F79D53E63D89FB87F4D9E6DC5949F5D9388BCFE9EBCB4C2F7CE497814CF40E845705F8F18DBF0F860DE0B1CC4A433EF74A5741F3202E958C082E0B76E16ECD5866AA0F5F3DF300
                        , ehR =
                            0x1604BE98D1A27CEC2D3FA4BD07B42799E07743071E4905D7DCE7F6992B21A27F14F55D0FE5A7810DF65CF07F2F2554658817E5A88D952282EA1B8310514C0B40FFF46F159965168
                        , ehS =
                            0x18249377C654B8588475510F7B797081F68C2F8CCCE49F730353B2DA3364B1CD3E984813E11BB791824038EA367BA74583AB97A69AF2D77FA691AA694E348E15DA76F5A44EC1F40
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x0308253C022D25F8A9EBCD24459DD6596590BDEC7895618EEE8A2623A98D2A2B2E7594EE6B7AD3A39D70D68CB4ED01CB28E2129F8E2CC0CC8DC7780657E28BCD655F0BE9B7D35A2
                        , ehR =
                            0x1E6D7FB237040EA1904CCBF0984B81B866DE10D8AA93B06364C4A46F6C9573FA288C8BDDCC0C6B984E6AA75B42E7BF82FF34D51DFFBD7C87FDBFAD971656185BD12E4B8372F4BF1
                        , ehS =
                            0x04F94550072ADA7E8C82B7E83577DD39959577799CDABCEA60E267F36F1BEB981ABF24E722A7F031582D2CC5D80DAA7C0DEEBBE1AC5E729A6DBB34A5D645B698719FCA409FBA370
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x0C5EE7070AF55F84EBC43A0D481458CEDE1DCEBB57720A3C92F59B4941A044FECFF4F703940F3121773595E880333772ACF822F2449E17C64DA286BCD65711DD5DA44D7155BF004
                        , ehR =
                            0x086C9E048EADD7D3D2908501086F3AF449A01AF6BEB2026DC381B39530BCDDBE8E854251CBD5C31E6976553813C11213E4761CB8CA2E5352240AD9FB9C635D55FAB13AE42E4EE4F
                        , ehS =
                            0x09FEE0A68F322B380217FCF6ABFF15D78C432BD8DD82E18B6BA877C01C860E24410F5150A44F979920147826219766ECB4E2E11A151B6A15BB8E2E825AC95BCCA228D8A1C9D3568
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x1D056563469E933E4BE064585D84602D430983BFBFD6885A94BA484DF9A7AB031AD6AC090A433D8EEDC0A7643EA2A9BC3B6299E8ABA933B4C1F2652BB49DAEE833155C8F1319908
                        , ehR =
                            0x1D055F499A3F7E3FC73D6E7D517B470879BDCB14ABC938369F23643C7B96D0242C1FF326FDAF1CCC8593612ACE982209658E73C24C9EC493B785608669DA74A5B7C9A1D8EA843BC
                        , ehS =
                            0x1621376C53CFE3390A0520D2C657B1FF0EBB10E4B9C2510EDC39D04FEBAF12B8502B098A8B8F842EA6E8EB9D55CFEF94B7FF6D145AC3FFCE71BD978FEA3EF8194D4AB5293A8F3EA
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x1DA875065B9D94DBE75C61848D69578BCC267935792624F9887B53C9AF9E43CABFC42E4C3F9A456BA89E717D24F1412F33CFD297A7A4D403B18B5438654C74D592D5022125E0C6B
                        , ehR =
                            0x18709BDE4E9B73D046CE0D48842C97063DA54DCCA28DCB087168FA37DA2BF5FDBE4720EE48D49EDE4DD5BD31AC0149DB8297BD410F9BC02A11EB79B60C8EE63AF51B65267D71881
                        , ehS =
                            0x12D8B9E98FBF1D264D78669E236319D8FFD8426C56AFB10C76471EE88D7F0AB1B158E685B6D93C850D47FB1D02E4B24527473DB60B8D1AEF26CEEBD3467B65A70FFDDC0DBB64D5F
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x04DDD0707E81BB56EA2D1D45D7FAFDBDD56912CAE224086802FEA1018DB306C4FB8D93338DBF6841CE6C6AB1506E9A848D2C0463E0889268843DEE4ACB552CFFCB858784ED116B2
                        , ehR =
                            0x1F5BF6B044048E0E310309FFDAC825290A69634A0D3592DBEE7BE71F69E45412F766AC92E174CC99AABAA5C9C89FCB187DFDBCC7A26765DB6D9F1EEC8A6127BBDFA5801E44E3BEC
                        , ehS =
                            0x1B44CBFB233BFA2A98D5E8B2F0B2C27F9494BEAA77FEB59CDE3E7AE9CB2E385BE8DA7B80D7944AA71E0654E5067E9A70E88E68833054EED49F28283F02B229123995AF37A6089F0
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x0141B53DC6E569D8C0C0718A58A5714204502FDA146E7E2133E56D19E905B79413457437095DE13CF68B5CF5C54A1F2E198A55D974FC3E507AFC0ACF95ED391C93CC79E3B3FE37C
                        , ehR =
                            0x11F61A6EFAB6D83053D9C52665B3542FF3F63BD5913E527BDBA07FBAF34BC766C2EC83163C5273243AA834C75FDDD1BC8A2BEAD388CD06C4EBA1962D645EEB35E92D44E8F2E081D
                        , ehS =
                            0x16BF6341876F051DF224770CC8BA0E4D48B3332568A2B014BC80827BAA89DE18D1AEBC73E3BE8F85A8008C682AAC7D5F0E9FB5ECBEFBB637E30E4A0F226D2C2AA3E569BB54AB72B
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x14842F97F263587A164B215DD0F912C588A88DC4AB6AF4C530ADC1226F16E086D62C14435E6BFAB56F019886C88922D2321914EE41A8F746AAA2B964822E4AC6F40EE2492B66824
                        , ehR =
                            0x0F1E50353A39EA64CDF23081D6BB4B2A91DD73E99D3DD5A1AA1C49B4F6E34A665EAD24FD530B9103D522609A395AF3EF174C85206F67EF84835ED1632E0F6BAB718EA90DF9E2DA0
                        , ehS =
                            0x0B385004D7596625028E3FDE72282DE4EDC5B4CE33C1127F21CC37527C90B7307AE7D09281B840AEBCECAA711B00718103DDB32B3E9F6A9FBC6AF23E224A73B9435F619D9C62527
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t163r2
        , ecPrivate = 0x35318FC447D48D7E6BC93B48617DDDEDF26AA658F
        , ecPublic =
            Point
                0x126CF562D95A1D77D387BA75A3EA3A1407F23425A
                0x7D7CB5273C94DA8CA93049AFDA18721C24672BD71
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x0707A94C3D352E0A9FE49FB12F264992152A20004
                        , ehR = 0x153FEBD179A69B6122DEBF5BC61EB947B24C93526
                        , ehS = 0x37AC9C670F8CF18045049BAE7DD35553545C19E49
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x3B24C5E2C2D935314EABF57A6484289B291ADFE3F
                        , ehR = 0x0A379E69C44F9C16EA3215EA39EB1A9B5D58CC955
                        , ehS = 0x04BAFF5308DA2A7FE2C1742769265AD3ED1D24E74
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x3D7086A59E6981064A9CDB684653F3A81B6EC0F0B
                        , ehR = 0x134E00F78FC1CB9501675D91C401DE20DDF228CDC
                        , ehS = 0x373273AEC6C36CB7BAFBB1903A5F5EA6A1D50B624
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x3B1E4443443486C7251A68EF184A936F05F8B17C7
                        , ehR = 0x29430B935AF8E77519B0CA4F6903B0B82E6A21A66
                        , ehS = 0x1EA1415306E9353FA5AA54BC7C2581DFBB888440D
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x2EDF5CFCAC7553C17421FDF54AD1D2EF928A879D2
                        , ehR = 0x0B2F177A99F9DF2D51CCAF55F015F326E4B65E7A0
                        , ehS = 0x0DF1FB4487E9B120C5E970EFE48F55E406306C3A1
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x10024F5B324CBC8954BA6ADB320CD3AB9296983B4
                        , ehR = 0x256D4079C6C7169B8BC92529D701776A269D56308
                        , ehS = 0x341D3FFEC9F1EB6A6ACBE88E3C86A1C8FDEB8B8E1
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x34F46DE59606D56C75406BFB459537A7CC280AA62
                        , ehR = 0x28ECC6F1272CE80EA59DCF32F7AC2D861BA803393
                        , ehS = 0x0AD4AE2C06E60183C1567D2B82F19421FE3053CE2
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x38145E3FFCA94E4DDACC20AD6E0997BD0E3B669D2
                        , ehR = 0x227DF377B3FA50F90C1CB3CDCBBDBA552C1D35104
                        , ehS = 0x1F7BEAD92583FE920D353F368C1960D0E88B46A56
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x375813210ECE9C4D7AB42DDC3C55F89189CF6DFFD
                        , ehR = 0x11811DAFEEA441845B6118A0DFEE8A0061231337D
                        , ehS = 0x36258301865EE48C5C6F91D63F62695002AB55B57
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x25AD8B393BC1E9363600FDA1A2AB6DF40079179A3
                        , ehR = 0x3B6BB95CA823BE2ED8E3972FF516EB8972D765571
                        , ehS = 0x13DC6F420628969DF900C3FCC48220B38BE24A541
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t233r1
        , ecPrivate = 0x07ADC13DD5BF34D1DDEEB50B2CE23B5F5E6D18067306D60C5F6FF11E5D3
        , ecPublic =
            Point
                0x0FB348B3246B473AA7FBB2A01B78D61B62C4221D0F9AB55FC72DB3DF478
                0x1162FA1F6C6ACF7FD8D19FC7D74BDD9104076E833898BC4C042A6E6BEBF
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x0A4E0B67A3A081C1B35D7BECEB5FE72A918B422B907145DB5416ED751CE
                        , ehR = 0x015CC6FD78BB06E0878E71465515EA5A21A2C18E6FC77B4B158DBEB3944
                        , ehS = 0x0822A4A6C2EB2DF213A5E90BF40377956365EE8C4B4A5A4E2EB9270CB6A
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x0F2B1C1E80BEB58283AAA79857F7B83BDF724120D0913606FD07F7FFB2C
                        , ehR = 0x05D9920B53471148E10502AB49AB7A3F11084820A074FD89883CF51BC1A
                        , ehS = 0x04D3938900C0A9AAA7080D1DFEB56CFB0FADABE4214536C7ED5117ED13A
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x034A53897B0BBDB484302E19BF3F9B34A2ABFED639D109A388DC52006B5
                        , ehR = 0x0A797F3B8AEFCE7456202DF1E46CCC291EA5A49DA3D4BDDA9A4B62D5E0D
                        , ehS = 0x01F6F81DA55C22DA4152134C661588F4BD6F82FDBAF0C5877096B070DC2
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x04D4670B28990BC92EEB49840B482A1FA03FE028D09F3D21F89C67ECA85
                        , ehR = 0x015E85A8D46225DD7E314A1C4289731FC14DECE949349FE535D11043B85
                        , ehS = 0x03F189D37F50493EFD5111A129443A662AB3C6B289129AD8C0CAC85119C
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x0DE108AAADA760A14F42C057EF81C0A31AF6B82E8FBCA8DC86E443AB549
                        , ehR = 0x03B62A4BF783919098B1E42F496E65F7621F01D1D466C46940F0F132A95
                        , ehS = 0x0F4BE031C6E5239E7DAA014CBBF1ED19425E49DAEB426EC9DF4C28A2E30
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x0250C5C90A4E2A3F8849FEBA87F0D0AE630AB18CBABB84F4FFFB36CEAC0
                        , ehR = 0x02F1FEDC57BE203E4C8C6B8C1CEB35E13C1FCD956AB41E3BD4C8A6EFB1F
                        , ehS = 0x05738EC8A8EDEA8E435EE7266AD3EDE1EEFC2CEBE2BE1D614008D5D2951
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x07BDB6A7FD080D9EC2FC84BFF9E3E15750789DC04290C84FED00E109BBD
                        , ehR = 0x0CCE175124D3586BA7486F7146894C65C2A4A5A1904658E5C7F9DF5FA5D
                        , ehS = 0x08804B456D847ACE5CA86D97BF79FD6335E5B17F6C0D964B5D0036C867E
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x00376886E89013F7FF4B5214D56A30D49C99F53F211A3AFE01AA2BDE12D
                        , ehR = 0x035C3D6DFEEA1CFB29B93BE3FDB91A7B130951770C2690C16833A159677
                        , ehS = 0x0600F7301D12AB376B56D4459774159ADB51F97E282FF384406AFD53A02
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x03726870DE75613C5E529E453F4D92631C03D08A7F63813E497D4CB3877
                        , ehR = 0x061602FC8068BFD5FB86027B97455D200EC603057446CCE4D76DB8EF42C
                        , ehS = 0x03396DD0D59C067BB999B422D9883736CF9311DFD6951F91033BD03CA8D
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x09CE5810F1AC68810B0DFFBB6BEEF2E0053BB937969AE7886F9D064A8C4
                        , ehR = 0x07E12CB60FDD614958E8E34B3C12DDFF35D85A9C5800E31EA2CC2EF63B1
                        , ehS = 0x0E8970FD99D836F3CC1C807A2C58760DE6EDAA23705A82B9CB1CE93FECC
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t283r1
        , ecPrivate =
            0x14510D4BC44F2D26F4553942C98073C1BD35545CEABB5CC138853C5158D2729EA408836
        , ecPublic =
            Point
                0x17E3409A13C399F0CA8A192F028D46E3446BCFFCDF51FF8A905ED2DED786E74F9C3E8A9
                0x47EFCBCC31C01D86D1992F7BFAC0277DBD02A6D289274099A2C0F039C8F59F318371B0E
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x277F389559667E8AE4B65DC056F8CE2872E1917E7CC59D17D485B0B98343206FBCCD441
                        , ehR = 0x201E18D48C6DB3D5D097C4DCE1E25587E1501FC3CF47BDB5B4289D79E273D6A9ACB8285
                        , ehS = 0x151AE05712B024CE617358260774C8CA8B0E7A7E72EF8229BF2ACE7609560CB30322C4F
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x14CC8FCFEECD6B999B4DC6084EBB06FDED0B44D5C507802CC7A5E9ECF36E69DA6AE23C6
                        , ehR = 0x143E878DDFD4DF40D97B8CD638B3C4706501C2201CF7108F2FB91478C11D69473246925
                        , ehS = 0x0CBF1B9717FEEA3AABB09D9654110144267098E0E1E8D0289A6211BE0EEDFDD86A3DB79
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x38C9D662188982943E080B794A4CFB0732DBA37C6F40D5B8CFADED6FF31C5452BA3F877
                        , ehR = 0x29FD82497FB3E5CEF65579272138DE59E2B666B8689466572B3B69A172CEE83BE145659
                        , ehS = 0x05A89D9166B40795AF0FE5958201B9C0523E500013CA12B4840EA2BC53F25F9B3CE87C0
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x21B7265DEBF90E6F988CFFDB62B121A02105226C652807CC324ED6FB119A287A72680AB
                        , ehR = 0x2F00689C1BFCD2A8C7A41E0DE55AE182E6463A152828EF89FE3525139B6603294E69353
                        , ehS = 0x1744514FE0A37447250C8A329EAAADA81572226CABA16F39270EE5DD03F27B1F665EB5D
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x20583259DC179D9DA8E5387E89BFF2A3090788CF1496BCABFE7D45BB120B0C811EB8980
                        , ehR = 0x0DA43A9ADFAA6AD767998A054C6A8F1CF77A562924628D73C62761847AD8286E0D91B47
                        , ehS = 0x1D118733AE2C88357827CAFC6F68ABC25C80C640532925E95CFE66D40F8792F3AC44C42
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK = 0x0185C57A743D5BA06193CE2AA47B07EF3D6067E5AE1A6469BCD3FC510128BA564409D82
                        , ehR = 0x05A408133919F2CDCDBE5E4C14FBC706C1F71BADAFEF41F5DE4EC27272FC1CA9366FBB2
                        , ehS = 0x012966272872C097FEA7BCE64FAB1A81982A773E26F6E4EF7C99969846E67CA9CBE1692
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK = 0x2E5C1F00677A0E015EC3F799FA9E9A004309DBD784640EAAF5E1CE64D3045B9FE9C1FA1
                        , ehR = 0x08F3824E40C16FF1DDA8DC992776D26F4A5981AB5092956C4FDBB4F1AE0A711EEAA10E5
                        , ehS = 0x0A64B91EFADB213E11483FB61C73E3EF63D3B44EEFC56EA401B99DCC60CC28E99F0F1FA
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK = 0x018A7D44F2B4341FEFE68F6BD8894960F97E08124AAB92C1FFBBE90450FCC9356C9AAA5
                        , ehR = 0x3597B406F5329D11A79E887847E5EC60861CCBB19EC61F252DB7BD549C699951C182796
                        , ehS = 0x0A6A100B997BC622D91701D9F5C6F6D3815517E577622DA69D3A0E8917C1CBE63ACD345
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK = 0x3C75397BA4CF1B931877076AF29F2E2F4231B117AB4B8E039F7F9704DE1BD3522F150B6
                        , ehR = 0x1BB490926E5A1FDC7C5AA86D0835F9B994EDA315CA408002AF54A298728D422EBF59E4C
                        , ehS = 0x36C682CFC9E2C89A782BFD3A191609D1F0C1910D5FD6981442070393159D65FBCC0A8BA
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK = 0x14E66B18441FA54C21E3492D0611D2B48E19DE3108D915FD5CA08E786327A2675F11074
                        , ehR = 0x19944AA68F9778C2E3D6E240947613E6DA60EFCE9B9B2C063FF5466D72745B5A0B25BA2
                        , ehS = 0x03F1567B3C5B02DF15C874F0EE22850824693D5ADC4663BAA19E384E550B1DD41F31EE6
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t409r1
        , ecPrivate =
            0x0494994CC325B08E7B4CE038BD9436F90B5E59A2C13C3140CD3AE07C04A01FC489F572CE0569A6DB7B8060393DE76330C624177
        , ecPublic =
            Point
                0x1A7055961CF1DA4B9A015B18B1524EF01FDD9B93FAEFC26FB1F2F828A7227B7031925DA0AC1A8A075C3B33554B222EA859C17E7
                0x18105C042F290736088F30AEC7AE7732A45DE47BCE0940113AB8132516D1E059B0F581FD581A9A3CB3A0AC42A1962738ADB86E6
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x042D8A2B34402757EB2CCFDDC3E6E96A7ADD3FDA547FC10A0CB77CFC720B4F9E16EEAAA2A8CC4E4A4B5DBF7D8AC4EA491859E60
                        , ehR =
                            0x0D8783188E1A540E2022D389E1D35B32F56F8C2BB5636B8ABF7718806B27A713EBAE37F63ECD4B61445CEF5801B62594EF3E982
                        , ehS =
                            0x03A6B4A80E204DB0DE12E7415C13C9EC091C52935658316B4A0C591216A3879154BEB1712560E346E7EF26517707435B55C3141
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x0C933F1DC4C70838C2AD16564715ACAF545BCDD8DC203D25AF3EC63949C65CB2E68AC1F60CA7EACA2A823F4E240927AA82CEEC5
                        , ehR =
                            0x0EE4F39ACC2E03CE96C3D9FCBAFA5C22C89053662F8D4117752A9B10F09ADFDA59DB061E247FE5321D6B170EE758ACE1BE4D157
                        , ehS =
                            0x00A2B83265B456A430A8BF27DCC8A9488B3F126C10F0D6D64BF7B8A218FAAF20E51A295A3AE78F205E5A4A6AE224C3639F1BB34
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x08EC42D13A3909A20C41BEBD2DFED8CACCE56C7A7D1251DF43F3E9E289DAE00E239F6960924AC451E125B784CB687C7F23283FD
                        , ehR =
                            0x02D8B1B31E33E74D7EB46C30FDE5AD2CA04EC8FE08FBA0E73BA5E568953AC5EA307C072942238DFC07F4A4D7C7C6A9F86436D17
                        , ehS =
                            0x079F7D471E6CB73234AF7F7C381D2CE15DE35BAF8BB68393B73235B3A26EC2DF4842CE433FB492D6E074E604D4870024D42189A
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x0DA881BCE3BA851485879EF8AC585A63F1540B9198ECB8A1096D70CB25A104E2F8A96B108AE76CB49CF34491ABC70E9D2AAD450
                        , ehR =
                            0x07BC638B7E7CE6FEE5E9C64A0F966D722D01BB4BC3F3A35F30D4CDDA92DFC5F7F0B4BBFE8065D9AD452FD77A1914BE3A2440C18
                        , ehS =
                            0x06D904429850521B28A32CBF55C7C0FDF35DC4E0BDA2552C7BF68A171E970E6788ACC0B9521EACB4796E057C70DD9B95FED5BFB
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x0750926FFAD7FF5DE85DF7960B3A4F9E3D38CF5A049BFC89739C48D42B34FBEE03D2C047025134CC3145B60AFD22A68DF0A7FB2
                        , ehR =
                            0x05D178DECAFD2D02A3DA0D8BA1C4C1D95EE083C760DF782193A9F7B4A8BE6FC5C21FD60613BCA65C063A61226E050A680B3ABD4
                        , ehS =
                            0x013B7581E98F6A63FBBCB3E49BCDA60F816DB230B888506D105DC229600497C3B46588C784BE3AA9343BEF82F7C9C80AEB63C3B
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x017E167EAB1850A3B38EE66BFE2270F2F6BFDAC5E2D227D47B20E75F0719161E6C74E9F23088F0C58B1E63BC6F185AD2EF4EAE6
                        , ehR =
                            0x049F54E7C10D2732B4638473053782C6919218BBEFCEC8B51640FC193E832291F05FA12371E9B448417B3290193F08EE9319195
                        , ehS =
                            0x0499E267DEC84E02F6F108B10E82172C414F15B1B7364BE8BFD66ADC0C5DE23FEE3DF0D811134C25AFE0E05A6672F98889F28F1
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x01ADEB94C19951B460A146B8275D81638C07735B38A525D76023AAF26AA8A058590E1D5B1E78AB3C91608BDA67CFFBE6FC8A6CC
                        , ehR =
                            0x0B1527FFAA7DD7C7E46B628587A5BEC0539A2D04D3CF27C54841C2544E1BBDB42FDBDAAF8671A4CA86DFD619B1E3732D7BB56F2
                        , ehS =
                            0x0442C68C044868DF4832C807F1EDDEBF7F5052A64B826FD03451440794063F52B022DF304F47403D4069234CA9EB4C964B37C02
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x06EBA3D58D0E0DFC406D67FC72EF0C943624CF40019D1E48C3B54CCAB0594AFD5DEE30AEBAA22E693DBCFECAD1A85D774313DAD
                        , ehR =
                            0x0BB27755B991D6D31757BCBF68CB01225A38E1CFA20F775E861055DD108ED7EA455E4B96B2F6F7CD6C6EC2B3C70C3EDDEB9743B
                        , ehS =
                            0x0C5BE90980E7F444B5F7A12C9E9AC7A04CA81412822DD5AD1BE7C45D5032555EA070864245CF69266871FEB8CD1B7EDC30EF6D5
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x0A45B787DB44C06DEAB846511EEDBF7BFCFD3BD2C11D965C92FC195F67328F36A2DC83C0352885DAB96B55B02FCF49DCCB0E2DA
                        , ehR =
                            0x04EFEB7098772187907C87B33E0FBBA4584226C50C11E98CA7AAC6986F8D3BE044E5B52D201A410B852536527724CA5F8CE6549
                        , ehS =
                            0x09574102FEB3EF87E6D66B94119F5A6062950FF4F902EA1E6BD9E2037F33FF991E31F5956C23AFE48FCDC557FD6F088C7C9B2B3
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x0B90F8A0E757E81D4EA6891766729C96A6D01F9AEDC0D334932D1F81CC4E1973A4F01C33555FF08530A5098CADB6EDAE268ABB5
                        , ehR =
                            0x07E0249C68536AE2AEC2EC30090340DA49E6DC9E9EEC8F85E5AABFB234B6DA7D2E9524028CF821F21C6019770474CC40B01FAF6
                        , ehS =
                            0x08125B5A03FB44AE81EA46D446130C2A415ECCA265910CA69D55F2453E16CD7B2DFA4E28C50FA8137F9C0C6CEE4CD37ABCCF6D8
                        }
                    ]
                }
            ]
        }
    , EntryCurve
        { ecName = SEC_t571r1
        , ecPrivate =
            0x028A04857F24C1C082DF0D909C0E72F453F2E2340CCB071F0E389BCA2575DA19124198C57174929AD26E348CF63F78D28021EF5A9BF2D5CBEAF6B7CCB6C4DA824DD5C82CFB24E11
        , ecPublic =
            Point
                0x4B4B3CE9377550140B62C1061763AA524814DDCEF37B00CD5CDE94F7792BB0E96758E55DA2E9FEA8FF2A8B6830AE1D57A9CA7A77FCB0836BF43EA5454CDD9FEAD5CCFE7375C6A83
                0x4453B18F261E7A0E7570CD72F235EA750438E43946FBEBD2518B696954767AA7849C1719E18E1C51652C28CA853426F15C09AA4B579487338ABC7F33768FADD61B5A3A6443A8189
        , ecMessages =
            [ EntryMessage
                { emMessage = "sample"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x2669FAFEF848AF67D437D4A151C3C5D3F9AA8BB66EDC35F090C9118F95BA0041B0993BE2EF55DAAF36B5B3A737C40DB1F6E3D93D97B8419AD6E1BB8A5D4A0E9B2E76832D4E7B862
                        , ehR =
                            0x147D3EB0EDA9F2152DFD014363D6A9CE816D7A1467D326A625FC4AB0C786E1B74DDF7CD4D0E99541391B266C704BB6B6E8DCCD27B460802E0867143727AA415555454321EFE5CB6
                        , ehS =
                            0x17319571CAF533D90D2E78A64060B9C53169AB7FC908947B3EDADC54C79CCF0A7920B4C64A4EAB6282AFE9A459677CDA37FD6DD50BEF18709590FE18B923BDF74A66B189A850819
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x2EAFAD4AC8644DEB29095BBAA88D19F31316434F1766AD4423E0B54DD2FE0C05E307758581B0DAED2902683BBC7C47B00E63E3E429BA54EA6BA3AEC33A94C9A24A6EF8E27B7677A
                        , ehR =
                            0x10F4B63E79B2E54E4F4F6A2DBC786D8F4A143ECA7B2AD97810F6472AC6AE20853222854553BE1D44A7974599DB7061AE8560DF57F2675BE5F9DD94ABAF3D47F1582B318E459748B
                        , ehS =
                            0x3BBEA07C6B269C2B7FE9AE4DDB118338D0C2F0022920A7F9DCFCB7489594C03B536A9900C4EA6A10410007222D3DAE1A96F291C4C9275D75D98EB290DC0EEF176037B2C7A7A39A3
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x15C2C6B7D1A070274484774E558B69FDFA193BDB7A23F27C2CD24298CE1B22A6CC9B7FB8CABFD6CF7C6B1CF3251E5A1CDDD16FBFED28DE79935BB2C631B8B8EA9CC4BCC937E669E
                        , ehR =
                            0x213EF9F3B0CFC4BF996B8AF3A7E1F6CACD2B87C8C63820000800AC787F17EC99C04BCEDF29A8413CFF83142BB88A50EF8D9A086AF4EB03E97C567500C21D865714D832E03C6D054
                        , ehS =
                            0x3D32322559B094E20D8935E250B6EC139AC4AAB77920812C119AF419FB62B332C8D226C6C9362AE3C1E4AABE19359B8428EA74EC8FBE83C8618C2BCCB6B43FBAA0F2CCB7D303945
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x0FEF0B68CB49453A4C6ECBF1708DBEEFC885C57FDAFB88417AAEFA5B1C35017B4B498507937ADCE2F1D9EFFA5FE8F5AEB116B804FD182A6CF1518FDB62D53F60A0FF6EB707D856B
                        , ehR =
                            0x375D8F49C656A0BBD21D3F54CDA287D853C4BB1849983CD891EF6CD6BB56A62B687807C16685C2C9BCA2663C33696ACCE344C45F3910B1DF806204FF731ECB289C100EF4D1805EC
                        , ehS =
                            0x1CDEC6F46DFEEE44BCE71D41C60550DC67CF98D6C91363625AC2553E4368D2DFB734A8E8C72E118A76ACDB0E58697940A0F3DF49E72894BD799450FC9E550CC04B9FF9B0380021C
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x3FF373833A06C791D7AD586AFA3990F6EF76999C35246C4AD0D519BFF180CA1880E11F2FB38B764854A0AE3BECDDB50F05AC4FCEE542F207C0A6229E2E19652F0E647B9C4882193
                        , ehR =
                            0x1C26F40D940A7EAA0EB1E62991028057D91FEDA0366B606F6C434C361F04E545A6A51A435E26416F6838FFA260C617E798E946B57215284182BE55F29A355E6024FE32A47289CF0
                        , ehS =
                            0x3691DE4369D921FE94EDDA67CB71FBBEC9A436787478063EB1CC778B3DCDC1C4162662752D28DEEDF6F32A269C82D1DB80C87CE4D3B662E03AC347806E3F19D18D6D4DE7358DF7E
                        }
                    ]
                }
            , EntryMessage
                { emMessage = "test"
                , emHashes =
                    [ EntryHash
                        { ehAlgorithm = HashAlg SHA1
                        , ehK =
                            0x019B506FD472675A7140E429AA5510DCDDC21004206EEC1B39B28A688A8FD324138F12503A4EFB64F934840DFBA2B4797CFC18B8BD0B31BBFF3CA66A4339E4EF9D771B15279D1DC
                        , ehR =
                            0x133F5414F2A9BC41466D339B79376038A64D045E5B0F792A98E5A7AA87E0AD016419E5F8D176007D5C9C10B5FD9E2E0AB8331B195797C0358BA05ECBF24ACE59C5F368A6C0997CC
                        , ehS =
                            0x3D16743AE9F00F0B1A500F738719C5582550FEB64689DA241665C4CE4F328BA0E34A7EF527ED13BFA5889FD2D1D214C11EB17D6BC338E05A56F41CAFF1AF7B8D574DB62EF0D0F21
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA224
                        , ehK =
                            0x333C711F8C62F205F926593220233B06228285261D34026232F6F729620C6DE12220F282F4206D223226705608688B20B8BA86D8DFE54F07A37EC48F253283AC33C3F5102C8CC3E
                        , ehR =
                            0x3048E76506C5C43D92B2E33F62B33E3111CEEB87F6C7DF7C7C01E3CDA28FA5E8BE04B5B23AA03C0C70FEF8F723CBCEBFF0B7A52A3F5C8B84B741B4F6157E69A5FB0524B48F31828
                        , ehS =
                            0x2C99078CCFE5C82102B8D006E3703E020C46C87C75163A2CD839C885550BA5CB501AC282D29A1C26D26773B60FBE05AAB62BFA0BA32127563D42F7669C97784C8897C22CFB4B8FA
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA256
                        , ehK =
                            0x328E02CF07C7B5B6D3749D8302F1AE5BFAA8F239398459AF4A2C859C7727A8123A7FE9BE8B228413FC8DC0E9DE16AF3F8F43005107F9989A5D97A5C4455DA895E81336710A3FB2C
                        , ehR =
                            0x184BC808506E11A65D628B457FDA60952803C604CC7181B59BD25AEE1411A66D12A777F3A0DC99E1190C58D0037807A95E5080FA1B2E5CCAA37B50D401CFFC3417C005AEE963469
                        , ehS =
                            0x27280D45F81B19334DBDB07B7E63FE8F39AC7E9AE14DE1D2A6884D2101850289D70EE400F26ACA5E7D73F534A14568478E59D00594981ABE6A1BA18554C13EB5E03921E4DC98333
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA384
                        , ehK =
                            0x2A77E29EAD9E811A9FDA0284C14CDFA1D9F8FA712DA59D530A06CDE54187E250AD1D4FB5788161938B8DE049616399C5A56B0737C9564C9D4D845A4C6A7CDFCBFF0F01A82BE672E
                        , ehR =
                            0x319EE57912E7B0FAA1FBB145B0505849A89C6DB1EC06EA20A6A7EDE072A6268AF6FD9C809C7E422A5F33C6C3326EAD7402467DF3272A1B2726C1C20975950F0F50D8324578F13EC
                        , ehS =
                            0x2CF3EA27EADD0612DD2F96F46E89AB894B01A10DF985C5FC099CFFE0EA083EB44BE682B08BFE405DAD5F37D0A2C59015BA41027E24B99F8F75A70B6B7385BF39BBEA02513EB880C
                        }
                    , EntryHash
                        { ehAlgorithm = HashAlg SHA512
                        , ehK =
                            0x21CE6EE4A2C72C9F93BDB3B552F4A633B8C20C200F894F008643240184BE57BB282A1645E47FBBE131E899B4C61244EFC2486D88CDBD1DD4A65EBDD837019D02628D0DCD6ED8FB5
                        , ehR =
                            0x2AA1888EAB05F7B00B6A784C4F7081D2C833D50794D9FEAF6E22B8BE728A2A90BFCABDC803162020AA629718295A1489EE7ED0ECB8AAA197B9BDFC49D18DDD78FC85A48F9715544
                        , ehS =
                            0x0AA5371FE5CA671D6ED9665849C37F394FED85D51FEF72DA2B5F28EDFB2C6479CA63320C19596F5E1101988E2C619E302DD05112F47E8823040CE540CD3E90DCF41DBC461744EE9
                        }
                    ]
                }
            ]
        }
    ]

testPublic :: PrivateKey -> PublicPoint -> TestTree
testPublic (PrivateKey curve key) pub =
    testCase "public" $
        pub @=? generateQ curve key

testNonce :: PrivateKey -> HashAlg -> ByteString -> Integer -> TestTree
testNonce key (HashAlg alg) msg nonc =
    testCase "nonce" $
        nonc @=? deterministicNonce alg key (hashWith alg msg) Just

testSignature
    :: PrivateKey -> HashAlg -> ByteString -> Integer -> Signature -> TestTree
testSignature key (HashAlg alg) msg nonc sig = testCase "signature" $
    case signWith nonc key alg msg of
        Nothing -> assertFailure "could not sign message"
        Just result -> sig @=? result

testVerify :: PublicKey -> HashAlg -> ByteString -> Signature -> TestTree
testVerify pub (HashAlg alg) msg sig =
    testCase "verify" $
        assertBool "signature verification failed" $
            verify alg pub sig msg

testEntry :: Entry -> TestTree
testEntry entry = testGroup (show entry) tests
  where
    tests =
        [ testPublic key $ publicPoint entry
        , testSignature
            key
            (hashAlgorithm entry)
            (message entry)
            (nonce entry)
            (signature entry)
        , testVerify pub (hashAlgorithm entry) (message entry) (signature entry)
        ]
    pub = PublicKey curve $ publicPoint entry
    key = PrivateKey curve $ privateNumber entry
    curve = getCurveByName $ curveName entry

testEntryNonce :: Entry -> TestTree
testEntryNonce entry = testGroup (show entry) tests
  where
    tests =
        [ testPublic key $ publicPoint entry
        , testNonce key (hashAlgorithm entry) (message entry) (nonce entry)
        , testSignature
            key
            (hashAlgorithm entry)
            (message entry)
            (nonce entry)
            (signature entry)
        , testVerify pub (hashAlgorithm entry) (message entry) (signature entry)
        ]
    pub = PublicKey curve $ publicPoint entry
    key = PrivateKey curve $ privateNumber entry
    curve = getCurveByName $ curveName entry

ecdsaTests :: TestTree
ecdsaTests =
    testGroup
        "ECDSA"
        [ testGroup "GEC 2" $ testEntry . normalize <$> gec2Entries
        , testGroup "RFC 6979" $ testEntryNonce . normalize <$> flatten rfc6979Entries
        ]
