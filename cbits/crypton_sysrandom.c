/*
 * The kernel's own random number generator, reached without a file
 * descriptor: getrandom(2) on Linux and FreeBSD, getentropy(3) on the
 * systems that have that instead.
 *
 * This is preferred over reading /dev/urandom because it needs no path and
 * no descriptor, so it still works where /dev is not mounted or not
 * populated -- a minimal container, a chroot, a sandbox -- and it cannot be
 * defeated by exhausting the descriptor table.
 *
 * Availability is decided at run time as well as at compile time: a binary
 * built against headers that declare getrandom can still run on a kernel
 * that does not implement it, and says so with ENOSYS.
 */

#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#if defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>
#ifdef SYS_getrandom
#define CRYPTON_SYSRANDOM_GETRANDOM 1
#endif
#elif defined(__FreeBSD__)
#include <sys/param.h>
#if __FreeBSD_version >= 1200000
#include <sys/random.h>
#define CRYPTON_SYSRANDOM_GETRANDOM 1
#endif
#elif defined(__APPLE__)
/* getentropy(3) is declared in sys/random.h on Darwin, since 10.12 -- but
 * macOS only.  Crypto.Random says iOS does not allow it, which is why that
 * platform builds with INSECURE_ENTROPY; until someone can try it there,
 * iOS keeps the path it has rather than gaining an untested one. */
#include <TargetConditionals.h>
#if defined(TARGET_OS_OSX) && TARGET_OS_OSX
#include <sys/random.h>
#define CRYPTON_SYSRANDOM_GETENTROPY 1
#endif
#elif defined(__OpenBSD__)
#include <unistd.h>
#define CRYPTON_SYSRANDOM_GETENTROPY 1
#elif defined(__NetBSD__)
#include <sys/param.h>
#if __NetBSD_Version__ >= 1000000000
#include <sys/random.h>
#define CRYPTON_SYSRANDOM_GETENTROPY 1
#endif
#endif

/* getentropy(3) refuses more than 256 bytes in one call. */
#define CRYPTON_GETENTROPY_MAX 256

#if defined(CRYPTON_SYSRANDOM_GETRANDOM)

static int sysrandom_once(uint8_t *buf, size_t n)
{
#if defined(__linux__)
	return (int) syscall(SYS_getrandom, buf, n, 0);
#else
	return (int) getrandom(buf, n, 0);
#endif
}

#elif defined(CRYPTON_SYSRANDOM_GETENTROPY)

static int sysrandom_once(uint8_t *buf, size_t n)
{
	if (n > CRYPTON_GETENTROPY_MAX)
		n = CRYPTON_GETENTROPY_MAX;
	if (getentropy(buf, n) != 0)
		return -1;
	return (int) n;
}

#else

static int sysrandom_once(uint8_t *buf, size_t n)
{
	(void) buf; (void) n;
	errno = ENOSYS;
	return -1;
}

#endif

/* Is the call there, on this kernel, right now?  A zero-length request
 * answers that without consuming anything. */
int crypton_sysrandom_available(void)
{
	uint8_t b;
	int r = sysrandom_once(&b, 0);
	return r < 0 ? 0 : 1;
}

/* Fill the buffer.  Returns the number of bytes written, which is n unless
 * the call failed for a reason other than being interrupted. */
int crypton_sysrandom_bytes(uint8_t *buf, int len)
{
	size_t n = (size_t) len;
	size_t done = 0;

	if (len < 0)
		return 0;
	while (done < n) {
		int r = sysrandom_once(buf + done, n - done);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;
		done += (size_t) r;
	}
	return (int) done;
}
