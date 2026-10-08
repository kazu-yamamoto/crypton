{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module      : Crypto.System.CPU
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Gives information about crypton runtime environment.
module Crypto.System.CPU (
    ProcessorOption,
    processorOptions,

    -- * What an x86 processor was found to have
    pattern AESNI,
    pattern PCLMUL,
    pattern RDRAND,
    pattern SSSE3,
    pattern AVX,
    pattern AVX2,
    pattern SHANI,
    pattern MOVBE,
    pattern ADX,
    pattern VAES,
    pattern VAES512,

    -- * What an AArch64 processor was found to have
    pattern NEON,
    pattern ARMAES,
    pattern ARMPMULL,
    pattern ARMSHA1,
    pattern ARMSHA2,
    pattern ARMSHA512,

    -- * Questions that do not name an architecture
    hasAESAcceleration,
    hasGHASHAcceleration,
) where

import Control.Monad (filterM)
import Data.List (sort)
import Data.Word (Word16)
import Foreign.C.Types (CInt (..), CUInt (..))
#ifdef SUPPORT_RDRAND
import Data.Maybe (isJust)
#endif

import Crypto.Internal.Compat

#ifdef SUPPORT_RDRAND
import Crypto.Random.Entropy.RDRand
import Crypto.Random.Entropy.Source
#endif

-- | A processor feature crypton looked for, and dispatches on where it
-- finds it.
--
-- This is a number with names rather than a sum of constructors, and the
-- names are pattern synonyms with no @COMPLETE@ pragma, so a @case@ over
-- them needs a catch-all and a feature named in a later release breaks
-- nothing that compiled against this one.  The same reason 'Show' is
-- written out below: a program built against an older crypton still says
-- something useful about a value from a newer one.
--
-- The names are the processor's, not the operation's.  'AESNI' is x86's
-- and 'ARMAES' is AArch64's, and a machine reports only the ones it has;
-- ask 'hasAESAcceleration' if the question is whether AES is fast here.
newtype ProcessorOption = ProcessorOption Word16
    deriving (Eq, Ord)

-- | Support for AES instructions, with flag @support_aesni@.
pattern AESNI :: ProcessorOption
pattern AESNI = ProcessorOption 0

-- | Support for CLMUL instructions, with flag @support_pclmuldq@.
pattern PCLMUL :: ProcessorOption
pattern PCLMUL = ProcessorOption 1

-- | Support for the RDRAND instruction, with flag @support_rdrand@.
pattern RDRAND :: ProcessorOption
pattern RDRAND = ProcessorOption 2

-- | Supplemental SSE3.
pattern SSSE3 :: ProcessorOption
pattern SSSE3 = ProcessorOption 3

-- | AVX, and an operating system that saves its registers.
pattern AVX :: ProcessorOption
pattern AVX = ProcessorOption 4

-- | AVX2, and an operating system that saves its registers.
pattern AVX2 :: ProcessorOption
pattern AVX2 = ProcessorOption 5

-- | The SHA extensions, @sha1rnds4@ and @sha256rnds2@ and their neighbours.
pattern SHANI :: ProcessorOption
pattern SHANI = ProcessorOption 6

-- | The byte-swapping load.
pattern MOVBE :: ProcessorOption
pattern MOVBE = ProcessorOption 7

-- | @MULX@, @ADCX@ and @ADOX@: the two independent carry chains.
pattern ADX :: ProcessorOption
pattern ADX = ProcessorOption 8

-- | The AES and carry-less multiply instructions in their 256-bit form.
pattern VAES :: ProcessorOption
pattern VAES = ProcessorOption 9

-- | The same pair in their 512-bit form.
pattern VAES512 :: ProcessorOption
pattern VAES512 = ProcessorOption 10

-- | Advanced SIMD, which is not optional on AArch64.
pattern NEON :: ProcessorOption
pattern NEON = ProcessorOption 11

-- | The ARMv8 AES instructions.
pattern ARMAES :: ProcessorOption
pattern ARMAES = ProcessorOption 12

-- | @PMULL@, the ARMv8 carry-less multiply.
pattern ARMPMULL :: ProcessorOption
pattern ARMPMULL = ProcessorOption 13

-- | The ARMv8 SHA-1 instructions.
pattern ARMSHA1 :: ProcessorOption
pattern ARMSHA1 = ProcessorOption 14

-- | The ARMv8 SHA-256 instructions.
pattern ARMSHA2 :: ProcessorOption
pattern ARMSHA2 = ProcessorOption 15

-- | The ARMv8.2 SHA-512 instructions, which are optional where SHA-256's
-- are not.
pattern ARMSHA512 :: ProcessorOption
pattern ARMSHA512 = ProcessorOption 16

-- | Named where the name is known, numbered where it is not, so that a
-- binary built against an older crypton can still print a value a newer one
-- produced.
instance Show ProcessorOption where
    show AESNI = "AESNI"
    show PCLMUL = "PCLMUL"
    show RDRAND = "RDRAND"
    show SSSE3 = "SSSE3"
    show AVX = "AVX"
    show AVX2 = "AVX2"
    show SHANI = "SHANI"
    show MOVBE = "MOVBE"
    show ADX = "ADX"
    show VAES = "VAES"
    show VAES512 = "VAES512"
    show NEON = "NEON"
    show ARMAES = "ARMAES"
    show ARMPMULL = "ARMPMULL"
    show ARMSHA1 = "ARMSHA1"
    show ARMSHA2 = "ARMSHA2"
    show ARMSHA512 = "ARMSHA512"
    show (ProcessorOption n) = "ProcessorOption " ++ show n

-- | Options which have been enabled at compile time and are supported by the
-- current CPU.
--
-- Sorted, and without repeats.  A machine reports the names of its own
-- architecture only: an AArch64 processor with AES says 'ARMAES', not
-- 'AESNI', which it does not have.
processorOptions :: [ProcessorOption]
processorOptions = unsafeDoIO $ do
    fromCPU <- filterM askC allOptions
    rdrand <- hasRDRand
    return (sort (fromCPU ++ [RDRAND | rdrand]))
  where
    -- RDRAND is not asked of C: the answer below opens the instruction and
    -- draws from it rather than trusting what cpuid says.
    allOptions = filter (/= RDRAND) [ProcessorOption n | n <- [0 .. 16]]
    askC (ProcessorOption n) =
        (/= 0) <$> crypton_cpu_option (fromIntegral n)
{-# NOINLINE processorOptions #-}

-- | Is there hardware AES on this machine?
--
-- The instructions have different names on different architectures, and a
-- caller that wants to know whether AES-GCM will be fast wants this rather
-- than either name.
hasAESAcceleration :: Bool
hasAESAcceleration =
    AESNI `elem` processorOptions || ARMAES `elem` processorOptions

-- | Is there a hardware carry-less multiply, which is what GHASH, and so
-- AES-GCM, spends its time in once AES itself is fast?
hasGHASHAcceleration :: Bool
hasGHASHAcceleration =
    PCLMUL `elem` processorOptions || ARMPMULL `elem` processorOptions

hasRDRand :: IO Bool
#ifdef SUPPORT_RDRAND
hasRDRand = fmap isJust getRDRand
  where
    getRDRand = entropyOpen :: IO (Maybe RDRand)
#else
hasRDRand = return False
#endif

foreign import ccall unsafe "crypton_cpu_option"
    crypton_cpu_option :: CUInt -> IO CInt
