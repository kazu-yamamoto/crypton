/*
 * One symbol, so that cbits/crypton_cpu.c can be linked on its own.
 *
 * The ML-KEM backend asks crypton_cpu.c whether this processor has AVX2.
 * That file also carries crypton_cpu_option, which the Haskell side calls
 * and which reaches into cbits/crypton_aes.c, so the linker wants
 * crypton_aes_cpu_init as well -- and behind it the whole AES build, which
 * has nothing to do with what is being measured here.  This stands in for
 * it.  Nothing in an ML-KEM driver calls it; if anything ever did, zeroes
 * say "no AES instructions", which is the safe answer.
 */
#include <stdint.h>
#include "crypton_cpu.h"

uint8_t *crypton_aes_cpu_init(void)
{
	static uint8_t none[CPU_OPTION_COUNT];
	return none;
}
