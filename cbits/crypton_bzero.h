/*
 * Erasing memory that the compiler is entitled to decide nobody reads.
 *
 * memset on an object that is about to die -- freed, or a local going out of
 * scope -- is a store to memory nothing can observe, and an optimizer may
 * drop it.  That is the whole reason explicit_bzero and memset_s exist.
 * Neither is everywhere, so this writes through a volatile pointer, which the
 * standard says cannot be elided.
 *
 * Use it wherever key material stops being needed.  Plain memset is still
 * right for memory that is about to be read again.
 */
#ifndef CRYPTON_BZERO_H
#define CRYPTON_BZERO_H

#include <stddef.h>
#include <stdint.h>

static inline void crypton_bzero(void *p, size_t n)
{
	volatile uint8_t *q = (volatile uint8_t *)p;

	while (n--)
		*q++ = 0;
}

#endif
