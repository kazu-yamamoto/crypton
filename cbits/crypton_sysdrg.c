/*
 * The generator behind MonadRandom IO.
 *
 * A ChaCha20 DRBG per operating system thread, seeded from a process-wide
 * DRBG, which is itself seeded from the system entropy pool with RDRAND
 * mixed in where there is one.  This is the shape RFC 9180's neighbours and
 * the other libraries have settled on, and it was asked for in #298.
 *
 * Per operating system thread and not per Haskell thread: a forkIO thread
 * moves between capabilities, so state kept against it would be shared by
 * threads running at the same time.  That is why the state is here and
 * reached through pthread_getspecific rather than held in Haskell.
 *
 * Three things force a reseed:
 *
 *   - a thread has produced CRYPTON_THREAD_RESEED bytes,
 *   - the process DRBG has issued CRYPTON_GLOBAL_RESEED bytes of seed,
 *   - the process has forked.
 *
 * The last one is the one that bites.  A child inherits its parent's state
 * and would otherwise produce the same stream; the generation counter below
 * is bumped in the child by a pthread_atfork handler, and every generator
 * compares against it before it answers.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "crypton_chacha.h"
#include "crypton_sha512.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

/* from crypton_sysrandom.c and crypton_rdrand.c */
int crypton_sysrandom_available(void);
int crypton_sysrandom_bytes(uint8_t *buf, int len);
#ifdef SUPPORT_RDRAND
int crypton_cpu_has_rdrand(void);
int crypton_get_rand_bytes(uint8_t *buffer, size_t len);
#endif

#define CHACHA_ROUNDS      20
#define SEED_KEY           32
#define SEED_IV             8
#define SEED_LEN           (SEED_KEY + SEED_IV)

#define CRYPTON_THREAD_RESEED  (1u << 20)
#define CRYPTON_GLOBAL_RESEED  (1u << 20)

typedef struct {
	crypton_chacha_context ctx;
	uint64_t used;
	uint32_t generation;
	int seeded;
} drg_t;

static drg_t global_drg;
static volatile uint32_t fork_generation = 0;

#ifdef _WIN32
static CRITICAL_SECTION global_lock;
/* Fls and not Tls: TlsAlloc has no destructor, so the state of every thread
 * that ever drew a byte would be left allocated and unscrubbed when the
 * thread ended.  FlsAlloc takes the callback that pthread_key_create does. */
static DWORD thread_slot;
static INIT_ONCE init_once = INIT_ONCE_STATIC_INIT;
#else
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_key_t thread_slot;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
#endif

static void scrub(void *p, size_t n)
{
	volatile uint8_t *q = (volatile uint8_t *) p;
	while (n--) *q++ = 0;
}

/*
 * Seed material for the process DRBG.
 *
 * Every source goes through SHA-512 rather than into the key directly, so
 * that a source which turns out to be weak cannot determine the result on
 * its own.  That is what #298 asks of RDRAND: mixed in, never alone.
 */
static int seed_from_system(uint8_t out[SEED_LEN])
{
	struct sha512_ctx h;
	uint8_t buf[64];
	uint8_t digest[64];
	int got;

	crypton_sha512_init(&h);

	/* The system call only.  Where there is none -- an old kernel, a BSD
	 * this does not know -- seeding fails and the caller keeps the path
	 * it has, rather than this file growing a second copy of the device
	 * reading that Crypto.Random.Entropy.Unix already does. */
	got = crypton_sysrandom_available() ? crypton_sysrandom_bytes(buf, 64) : 0;
	if (got <= 0) {
		/* Nothing else here is a seed on its own, so there is nothing to
		 * go on with: return before drawing anything that would only be
		 * thrown away. */
		scrub(&h, sizeof h);
		scrub(buf, sizeof buf);
		return 0;
	}
	crypton_sha512_update(&h, buf, (uint32_t) got);

#ifdef SUPPORT_RDRAND
	/* Defence in depth rather than a second source.  On Linux the kernel
	 * already feeds RDRAND and RDSEED into the pool the call above draws
	 * from, so this is not independent of it; what it covers is that pool
	 * having gone wrong.  It is never asked alone -- the return above saw
	 * to that -- and it is not counted anywhere as entropy obtained. */
	if (crypton_cpu_has_rdrand()) {
		got = crypton_get_rand_bytes(buf, 32);
		if (got > 0)
			crypton_sha512_update(&h, buf, (uint32_t) got);
	}
#endif

	crypton_sha512_finalize(&h, digest);
	memcpy(out, digest, SEED_LEN);

	scrub(&h, sizeof h);
	scrub(buf, sizeof buf);
	scrub(digest, sizeof digest);
	return 1;
}

static void drg_seed(drg_t *d, const uint8_t seed[SEED_LEN])
{
	crypton_chacha_init(&d->ctx, CHACHA_ROUNDS, SEED_KEY, seed,
	                    SEED_IV, seed + SEED_KEY);
	d->used = 0;
	d->generation = fork_generation;
	d->seeded = 1;
}

/*
 * Forget the key that produced the bytes just handed out.
 *
 * Without this the key stands until the next reseed, and anyone who reads a
 * generator's state can wind the counter back and reproduce everything it
 * has issued since -- up to CRYPTON_THREAD_RESEED bytes that were meant to
 * be secret.  Taking the next forty bytes of keystream as the new key and
 * nonce, and dropping the old ones, puts that out of reach one step after
 * it is issued: ChaCha20 does not run backwards, and the key that would
 * have been needed is gone.  It is what arc4random does.
 *
 * crypton_chacha_init memsets the whole context, so the counter returns to
 * zero and the tail of a part-used block goes with the old key rather than
 * being handed out under the new one.
 *
 * d->used is not touched.  It counts what callers were given, which is what
 * the reseed interval is written in terms of; these forty bytes are the
 * cost of the rekey and not an answer to anybody.
 */
static void drg_rekey(drg_t *d)
{
	uint8_t next[SEED_LEN];

	crypton_chacha_generate(next, &d->ctx, SEED_LEN);
	crypton_chacha_init(&d->ctx, CHACHA_ROUNDS, SEED_KEY, next,
	                    SEED_IV, next + SEED_KEY);
	scrub(next, sizeof next);
}

static int drg_stale(const drg_t *d, uint64_t limit)
{
	return !d->seeded || d->used >= limit || d->generation != fork_generation;
}

/* Bytes from the process DRBG, which is only ever asked for seed material. */
static int global_bytes(uint8_t *out, uint32_t len)
{
	int ok = 1;

#ifdef _WIN32
	EnterCriticalSection(&global_lock);
#else
	pthread_mutex_lock(&global_lock);
#endif
	if (drg_stale(&global_drg, CRYPTON_GLOBAL_RESEED)) {
		uint8_t seed[SEED_LEN];
		ok = seed_from_system(seed);
		if (ok)
			drg_seed(&global_drg, seed);
		scrub(seed, sizeof seed);
	}
	if (ok) {
		crypton_chacha_generate(out, &global_drg.ctx, len);
		global_drg.used += len;
		drg_rekey(&global_drg);
	}
#ifdef _WIN32
	LeaveCriticalSection(&global_lock);
#else
	pthread_mutex_unlock(&global_lock);
#endif
	return ok;
}

#ifdef _WIN32
static void WINAPI thread_free(void *p)
#else
static void thread_free(void *p)
#endif
{
	if (p) {
		scrub(p, sizeof(drg_t));
		free(p);
	}
}

#ifndef _WIN32
/* All three handlers, not just the child's.  The child's first draw has to
 * reseed -- the generation has changed -- and reseeding takes global_lock.
 * A fork made while another thread held it would hand the child a mutex
 * locked by a thread that did not come across, and the child would wait on
 * it for ever.  So the lock is taken before the fork and released on both
 * sides of it, which is the state the child needs it in. */
static void before_fork(void)
{
	pthread_mutex_lock(&global_lock);
}

static void after_fork_in_parent(void)
{
	pthread_mutex_unlock(&global_lock);
}

static void after_fork_in_child(void)
{
	pthread_mutex_unlock(&global_lock);
	fork_generation++;
}
#endif

#ifdef CRYPTON_SYSDRG_TESTING
/* For cbits/tests/sysdrg and nothing else: hold and release the process
 * generator's lock, so that a fork can be made to happen while another
 * thread holds it.  Nothing outside that test declares these, and the
 * library is never built with this defined. */
void crypton_sysdrg_test_lock(void);
void crypton_sysdrg_test_unlock(void);

static drg_t *this_thread(void);

/* The calling thread's ChaCha key, which is d[4..11] of the state.  A test
 * uses it to ask whether the key that produced a draw is still there
 * afterwards; see "a draw replaces the key that made it" in
 * cbits/tests/sysdrg. */
void crypton_sysdrg_test_key(uint8_t out[32]);

void crypton_sysdrg_test_key(uint8_t out[32])
{
	drg_t *d = this_thread();
	int i;

	if (!d)
		return;
	for (i = 0; i < 8; i++) {
		uint32_t w = d->ctx.st.d[4 + i];
		out[i * 4 + 0] = (uint8_t) (w);
		out[i * 4 + 1] = (uint8_t) (w >> 8);
		out[i * 4 + 2] = (uint8_t) (w >> 16);
		out[i * 4 + 3] = (uint8_t) (w >> 24);
	}
}

void crypton_sysdrg_test_lock(void)
{
#ifndef _WIN32
	pthread_mutex_lock(&global_lock);
#endif
}

void crypton_sysdrg_test_unlock(void)
{
#ifndef _WIN32
	pthread_mutex_unlock(&global_lock);
#endif
}
#endif

#ifdef _WIN32
static BOOL CALLBACK init_slot(PINIT_ONCE o, PVOID p, PVOID *c)
{
	(void) o; (void) p; (void) c;
	InitializeCriticalSection(&global_lock);
	thread_slot = FlsAlloc(thread_free);
	return TRUE;
}
#else
static void init_slot(void)
{
	pthread_key_create(&thread_slot, thread_free);
	pthread_atfork(before_fork, after_fork_in_parent, after_fork_in_child);
}
#endif

static drg_t *this_thread(void)
{
	drg_t *d;

#ifdef _WIN32
	InitOnceExecuteOnce(&init_once, init_slot, NULL, NULL);
	if (thread_slot == FLS_OUT_OF_INDEXES)
		return NULL;
	d = (drg_t *) FlsGetValue(thread_slot);
#else
	pthread_once(&init_once, init_slot);
	d = (drg_t *) pthread_getspecific(thread_slot);
#endif
	if (!d) {
		d = (drg_t *) calloc(1, sizeof(drg_t));
		if (!d)
			return NULL;
#ifdef _WIN32
		if (!FlsSetValue(thread_slot, d)) {
			free(d);
			return NULL;
		}
#else
		if (pthread_setspecific(thread_slot, d) != 0) {
			free(d);
			return NULL;
		}
#endif
	}
	return d;
}

/* Returns the number of bytes written, which is len unless there was no
 * seed to be had -- and then it is 0, so that the caller can say so rather
 * than hand back a buffer it cannot vouch for. */
int crypton_sysdrg_bytes(uint8_t *out, int len)
{
	drg_t *d;

	if (len < 0)
		return 0;
	d = this_thread();
	if (!d)
		return 0;

	if (drg_stale(d, CRYPTON_THREAD_RESEED)) {
		uint8_t seed[SEED_LEN];
		int ok = global_bytes(seed, SEED_LEN);
		if (ok)
			drg_seed(d, seed);
		scrub(seed, sizeof seed);
		if (!ok)
			return 0;
	}

	crypton_chacha_generate(out, &d->ctx, (uint32_t) len);
	d->used += (uint64_t) len;
	drg_rekey(d);
	return len;
}

/* For the tests: how many times the process has been seen to fork. */
uint32_t crypton_sysdrg_generation(void)
{
	return fork_generation;
}

/* For the tests: bytes this thread's generator has produced since it was
 * last seeded.  A generator shared between threads would carry the first
 * thread's count into the second; a per-thread one starts again at zero,
 * and that is the only way from outside to tell the two apart. */
uint64_t crypton_sysdrg_thread_used(void)
{
	drg_t *d = this_thread();
	return d ? d->used : 0;
}
