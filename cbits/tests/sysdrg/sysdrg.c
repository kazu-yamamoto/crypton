#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

void crypton_sysdrg_test_key(uint8_t out[32]);
void crypton_sysdrg_test_lock(void);
void crypton_sysdrg_test_unlock(void);
int crypton_sysdrg_bytes(uint8_t *out, int len);
uint32_t crypton_sysdrg_generation(void);
uint64_t crypton_sysdrg_thread_used(void);
static uint64_t used_in_thread;

static int fail = 0;
static void check(const char *what, int ok) {
    printf("%-52s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fail = 1;
}

/* Holds the process generator's lock for a moment, so that a fork can be
 * made to happen while it is held.  Releasing after a delay rather than on
 * demand is deliberate: a prepare handler has to be able to take the lock,
 * and a holder that waited to be told would stop the fork instead of the
 * child. */
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
static int holding = 0;

static void *lock_holder(void *arg) {
    (void) arg;
    crypton_sysdrg_test_lock();
    pthread_mutex_lock(&gate);
    holding = 1;
    pthread_cond_broadcast(&gate_cv);
    pthread_mutex_unlock(&gate);
    usleep(200000);
    crypton_sysdrg_test_unlock();
    return NULL;
}

static void *thread_body(void *arg) {
    uint8_t *out = (uint8_t *) arg;
    check("a second OS thread gets bytes", crypton_sysdrg_bytes(out, 32) == 32);
    used_in_thread = crypton_sysdrg_thread_used();
    return NULL;
}

int main(void) {
    uint8_t a[32], b[32], big[4096];
    memset(a, 0, 32); memset(b, 0, 32);

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
    check("the fork was noticed", crypton_sysdrg_generation() == 0);

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

    /* A fork while another thread holds the process generator's lock.  The
     * child's first draw has to reseed, the generation having changed, and
     * reseeding takes that lock.  With no prepare and parent handlers the
     * child inherits it locked and waits on it for ever -- the thread that
     * would release it did not come across the fork.  The alarm is what
     * turns that into a failure rather than a hung test run. */
    pthread_t holder;
    if (pthread_create(&holder, NULL, lock_holder, NULL) != 0) {
        perror("pthread_create"); return 2;
    }
    pthread_mutex_lock(&gate);
    while (!holding) pthread_cond_wait(&gate_cv, &gate);
    pthread_mutex_unlock(&gate);

    pid_t locked_pid = fork();
    if (locked_pid == 0) {
        uint8_t c[32];
        alarm(5);
        _exit(crypton_sysdrg_bytes(c, 32) == 32 ? 0 : 1);
    }
    pthread_join(holder, NULL);
    int locked_status = 0;
    waitpid(locked_pid, &locked_status, 0);
    check("a child forked while the lock was held can draw",
          WIFEXITED(locked_status) && WEXITSTATUS(locked_status) == 0);

    return fail;
}
