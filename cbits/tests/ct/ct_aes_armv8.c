/* The same driver as ct_aes.c, built against the AArch64 implementation
 * instead of the table-driven C.
 *
 * AESE, AESMC and PMULL look nothing up and branch on nothing, so this one
 * must report nothing at all -- not "nothing unknown", nothing.  The
 * table-driven run of the same driver is what keeps that honest: if the
 * marking stopped reaching the code, that run would fall silent and fail,
 * and a silence here would mean no more than a silence there.
 *
 * Until this existed the constant-time harness ran only on x86-64, so
 * crypton's AArch64 AES and GHASH had never been put to it. */
#include "ct_aes.c"
