#ifndef CRYPTON_MEMXOR_H
#define CRYPTON_MEMXOR_H

#include <stdint.h>

void crypton_memxor(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint32_t len);

#endif
