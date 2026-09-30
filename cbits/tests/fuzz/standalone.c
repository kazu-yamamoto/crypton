/* A main for the harnesses, for where there is no fuzzer.
 *
 * Apple's clang ships no libFuzzer runtime, so this replays the committed
 * corpus and then a deterministic stream of generated inputs.  That says the
 * harness is wired up and that the sanitizers are clean on what it feeds --
 * it is not a fuzzing campaign and does not explore anything.  The campaign
 * runs in CI, where clang has the runtime.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint64_t s0 = 0x243f6a8885a308d3ULL, s1 = 0x13198a2e03707344ULL;
static uint64_t rnd(void)
{
	uint64_t x = s0, y = s1;
	s0 = y;
	x ^= x << 23;
	s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
	return s1 + y;
}

int main(int argc, char **argv)
{
	static uint8_t buf[4096];
	long rounds = argc > 2 ? strtol(argv[2], NULL, 10) : 20000;
	long i;
	int replayed = 0;

	if (argc > 1) {
		DIR *d = opendir(argv[1]);
		struct dirent *e;
		if (d) {
			while ((e = readdir(d)) != NULL) {
				char path[1024];
				FILE *f;
				size_t n;
				if (e->d_name[0] == '.')
					continue;
				snprintf(path, sizeof path, "%s/%s", argv[1], e->d_name);
				f = fopen(path, "rb");
				if (!f)
					continue;
				n = fread(buf, 1, sizeof buf, f);
				fclose(f);
				LLVMFuzzerTestOneInput(buf, n);
				replayed++;
			}
			closedir(d);
		}
	}

	for (i = 0; i < rounds; i++) {
		size_t n = (size_t)(rnd() % sizeof buf);
		size_t j;
		for (j = 0; j < n; j++)
			buf[j] = (uint8_t)(rnd() >> 24);
		LLVMFuzzerTestOneInput(buf, n);
	}
	printf("replayed %d corpus input(s), then %ld generated\n", replayed, rounds);
	return 0;
}
