/* The calibration.  This harness reads one byte past a buffer when the input
 * opens with a four-byte marker.  Four bytes is the point: one chance in
 * 2^32 puts it out of reach of throwing random input at the harness, while a
 * fuzzer that watches which comparisons it got past finds it in seconds.  So
 * a campaign that does not report this one is not fuzzing, and the silence of
 * the harnesses beside it means nothing.
 *
 * Round five believed a ThreadSanitizer zero that meant nothing, and round
 * ten twice believed a scrubbing zero that meant nothing.  This is cheaper
 * than learning it a third time.
 *
 * Replaying the corpus is not expected to reach it, and run.sh says so.
 */
#include "tests/fuzz/fuzz.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *buf;
	int r;

	if (size < 5)
		return 0;
	if (data[0] != 0xde || data[1] != 0xad)
		return 0;
	if (data[2] != 0xbe || data[3] != 0xef)
		return 0;

	/* On the heap, not the stack.  A compiler that can see the size of a
	 * local can also see that reading past it is undefined and remove the
	 * read, which is what the first attempt at this did: the campaign found
	 * nothing because by then there was nothing left to find.  It cannot
	 * reason that way about what malloc returned. */
	buf = (uint8_t *)malloc(16);
	if (!buf)
		return 0;
	memset(buf, 0, 16);
	r = buf[16] == data[4] ? 1 : 0;      /* deliberately one past the end */
	free(buf);
	return r;
}
