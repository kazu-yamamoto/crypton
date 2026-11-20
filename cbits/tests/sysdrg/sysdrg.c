#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

void crypton_sysdrg_test_key(uint8_t out[32]);
int crypton_sysdrg_bytes(uint8_t *out, int len);
uint32_t crypton_sysdrg_generation(void);
uint64_t crypton_sysdrg_thread_used(void);
void crypton_sysdrg_reseed(void);
void crypton_sysdrg_test_save(void);
void crypton_sysdrg_test_restore(void);
void crypton_sysdrg_set_mode(int mode, uint32_t interval_ms);
int crypton_sysdrg_get_mode(void);
uint32_t crypton_sysdrg_get_interval(void);
void crypton_sysdrg_test_shift_realtime(int64_t ms);
static uint64_t used_in_thread;

static int fail = 0;
static void check(const char *what, int ok) {
    printf("%-52s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fail = 1;
}

static void *thread_body(void *arg) {
    uint8_t *out = (uint8_t *) arg;
    check("a second OS thread gets bytes", crypton_sysdrg_bytes(out, 32) == 32);
    used_in_thread = crypton_sysdrg_thread_used();
    return NULL;
}

/* Draws, waits while the main thread reseeds, and draws again; its used
 * count after the second draw says whether that draw was reseeded. */
static pthread_mutex_t step = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t step_cv = PTHREAD_COND_INITIALIZER;
static int stage = 0;

static void *draw_across_reseed(void *arg) {
    uint8_t out[32];
    (void) arg;
    crypton_sysdrg_bytes(out, 32);
    crypton_sysdrg_bytes(out, 32);
    pthread_mutex_lock(&step);
    stage = 1;
    pthread_cond_broadcast(&step_cv);
    while (stage != 2) pthread_cond_wait(&step_cv, &step);
    pthread_mutex_unlock(&step);
    crypton_sysdrg_bytes(out, 32);
    used_in_thread = crypton_sysdrg_thread_used();
    return NULL;
}

int main(void) {
    uint8_t a[32], b[32], big[4096];
    memset(a, 0, 32); memset(b, 0, 32);

    check("per draw is the default", crypton_sysdrg_get_mode() == 0);
    check("the default interval is 10 ms", crypton_sysdrg_get_interval() == 10);

    /* The per-thread generator, without the time limit so that a slow
     * machine does not reseed in the middle of a check. */
    crypton_sysdrg_set_mode(1, 0);

    check("asking for 32 bytes gives 32", crypton_sysdrg_bytes(a, 32) == 32);
    check("asking again gives something else",
          crypton_sysdrg_bytes(b, 32) == 32 && memcmp(a, b, 32) != 0);
    check("a 4096-byte request is filled", crypton_sysdrg_bytes(big, 4096) == 4096);
    check("zero length is fine", crypton_sysdrg_bytes(a, 0) == 0);

    /* two OS threads must not share a stream.  The main thread has already
     * produced over 4 KiB by here, so a shared generator would show it. */
    uint8_t t1[32], t2[32];
    pthread_t p1, p2;
    pthread_create(&p1, NULL, thread_body, t1);
    pthread_join(p1, NULL);
    pthread_create(&p2, NULL, thread_body, t2);
    pthread_join(p2, NULL);
    check("two OS threads do not produce the same bytes", memcmp(t1, t2, 32) != 0);
    check("a new OS thread starts its own stream, not the main one's",
          used_in_thread == 32);

    /* crossing the per-thread reseed limit (1 MiB) must not repeat */
    uint8_t before[32], after[32];
    crypton_sysdrg_bytes(before, 32);
    for (int i = 0; i < 1100; i++) { uint8_t junk[1024]; crypton_sysdrg_bytes(junk, 1024); }
    crypton_sysdrg_bytes(after, 32);
    check("output after a reseed differs from before", memcmp(before, after, 32) != 0);

    /* fork: parent and child must diverge */
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); return 2; }
    uint8_t parent[32], child[32];
    uint32_t g_fork = crypton_sysdrg_generation();
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        crypton_sysdrg_bytes(child, 32);
        ssize_t w = write(fds[1], child, 32);
        _exit(w == 32 ? 0 : 1);
    }
    close(fds[1]);
    crypton_sysdrg_bytes(parent, 32);
    ssize_t r = read(fds[0], child, 32);
    int status = 0; waitpid(pid, &status, 0);
    check("the child was able to produce bytes", r == 32 && status == 0);
    check("parent and child do not produce the same bytes", memcmp(parent, child, 32) != 0);
    check("the fork was noticed", crypton_sysdrg_generation() == g_fork);

    /* Backtracking resistance.  The key that produced a draw is replaced
     * once the bytes are out, so a state read afterwards is not the state
     * that made them and cannot be wound back to remake them.  Comparing
     * the key before and against the key after is the whole of it: without
     * the rekey it is the same key and the counter alone says where to
     * start. */
    uint8_t key_before[32], key_after[32], drawn[32];
    memset(key_before, 0, 32); memset(key_after, 0, 32);
    crypton_sysdrg_test_key(key_before);
    crypton_sysdrg_bytes(drawn, 32);
    crypton_sysdrg_test_key(key_after);
    check("a draw replaces the key that made it",
          memcmp(key_before, key_after, 32) != 0);

    /* An explicit reseed counts as a generation, and the next draw on this
     * thread and on another starts from a fresh seed: a used count of just
     * that draw. */
    uint32_t g0 = crypton_sysdrg_generation();
    uint8_t x[32];
    crypton_sysdrg_bytes(x, 32);
    pthread_t other;
    pthread_create(&other, NULL, draw_across_reseed, NULL);
    pthread_mutex_lock(&step);
    while (stage != 1) pthread_cond_wait(&step_cv, &step);
    crypton_sysdrg_reseed();
    stage = 2;
    pthread_cond_broadcast(&step_cv);
    pthread_mutex_unlock(&step);
    pthread_join(other, NULL);
    check("a reseed is counted", crypton_sysdrg_generation() == g0 + 1);
    crypton_sysdrg_bytes(x, 32);
    check("this thread reseeds on its next draw", crypton_sysdrg_thread_used() == 32);
    check("another thread reseeds on its next draw", used_in_thread == 32);

    /* A restore from a saved image.  Two copies of one image draw the same
     * bytes -- that is the problem -- and a reseed after the restore is what
     * makes them differ. */
    uint8_t first[32], second[32], third[32];
    crypton_sysdrg_test_save();
    crypton_sysdrg_bytes(first, 32);
    crypton_sysdrg_test_restore();
    crypton_sysdrg_bytes(second, 32);
    check("two copies of one image draw the same bytes", memcmp(first, second, 32) == 0);
    crypton_sysdrg_test_restore();
    crypton_sysdrg_reseed();
    crypton_sysdrg_bytes(third, 32);
    check("a reseed after the restore draws other bytes", memcmp(first, third, 32) != 0);

    /* The time limit: no reseed inside the interval, one after it. */
    crypton_sysdrg_set_mode(1, 1000);
    crypton_sysdrg_bytes(x, 32);
    crypton_sysdrg_bytes(x, 32);
    check("no reseed inside the interval", crypton_sysdrg_thread_used() == 64);
    crypton_sysdrg_set_mode(1, 20);
    crypton_sysdrg_bytes(x, 32);
    usleep(60 * 1000);
    crypton_sysdrg_bytes(x, 32);
    check("a reseed once the interval has passed", crypton_sysdrg_thread_used() == 32);

    /* A CRIU restore keeps the monotonic clock going on from the image and
     * moves realtime by the time away: a copy reseeds on its first draw. */
    crypton_sysdrg_set_mode(1, 0);
    crypton_sysdrg_bytes(x, 32);
    crypton_sysdrg_test_save();
    crypton_sysdrg_bytes(first, 32);
    crypton_sysdrg_test_restore();
    crypton_sysdrg_bytes(second, 32);
    check("without a jump a restored copy repeats", memcmp(first, second, 32) == 0);
    crypton_sysdrg_test_restore();
    crypton_sysdrg_test_shift_realtime(5000);
    crypton_sysdrg_bytes(second, 32);
    check("a realtime jump reseeds a restored copy", memcmp(first, second, 32) != 0);
    crypton_sysdrg_test_shift_realtime(-200);
    crypton_sysdrg_bytes(x, 32);
    check("a small realtime step does not reseed", crypton_sysdrg_thread_used() == 64);

    /* Per draw: nothing kept, so two copies of one image differ with no
     * reseed at all, and the per-thread generator is not touched. */
    crypton_sysdrg_set_mode(0, 10);
    check("the mode can be set back to per draw", crypton_sysdrg_get_mode() == 0);
    uint64_t used = crypton_sysdrg_thread_used();
    crypton_sysdrg_test_save();
    check("per draw gives bytes", crypton_sysdrg_bytes(first, 32) == 32);
    crypton_sysdrg_test_restore();
    crypton_sysdrg_bytes(second, 32);
    check("per draw: two copies of one image differ", memcmp(first, second, 32) != 0);
    check("per draw does not use the thread's generator",
          crypton_sysdrg_thread_used() == used);
    check("per draw fills a large request", crypton_sysdrg_bytes(big, 4096) == 4096);
    pthread_create(&p1, NULL, thread_body, t1);
    pthread_join(p1, NULL);
    check("per draw: another thread differs", memcmp(t1, first, 32) != 0);

    return fail;
}
