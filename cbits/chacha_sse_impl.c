/*
 * Included from chacha_sse2.c once per instruction set, with SIZED()
 * naming the functions, ROL() rotating a lane and TARGET saying what the
 * functions may use.  The body is identical; only the two rotates by
 * sixteen and eight differ, and only because SSSE3 can do each in one
 * PSHUFB where SSE2 needs a shift, a shift and an or.
 */

/*
 * Four blocks with counters d[12] .. d[12]+3.  The caller keeps the
 * state's counter and only calls this when those four do not carry into
 * d[13].
 */
TARGET
static void SIZED(core4)(int rounds, block out[4], const crypton_chacha_state *in)
{
	__m128i v0, v1, v2, v3, v4, v5, v6, v7;
	__m128i v8, v9, v10, v11, v12, v13, v14, v15;
	const uint32_t c = in->d[12];
	int i;

	/*
	 * Sixteen registers hold the working state and the machine has
	 * sixteen, so the initial state is read again at the end rather than
	 * kept in a second set.
	 */
#define SET(n) v##n = _mm_set1_epi32((int) in->d[n])
	SET(0);  SET(1);  SET(2);  SET(3);
	SET(4);  SET(5);  SET(6);  SET(7);
	SET(8);  SET(9);  SET(10); SET(11);
	         SET(13); SET(14); SET(15);
#undef SET
	v12 = _mm_setr_epi32((int) c, (int) (c + 1), (int) (c + 2), (int) (c + 3));

#define QR(a, b, cc, d)                                            \
	a = _mm_add_epi32(a, b); d = ROL(_mm_xor_si128(d, a), 16);  \
	cc = _mm_add_epi32(cc, d); b = ROL(_mm_xor_si128(b, cc), 12); \
	a = _mm_add_epi32(a, b); d = ROL(_mm_xor_si128(d, a),  8);  \
	cc = _mm_add_epi32(cc, d); b = ROL(_mm_xor_si128(b, cc),  7)

	for (i = rounds; i > 0; i -= 2) {
		QR(v0, v4, v8,  v12);
		QR(v1, v5, v9,  v13);
		QR(v2, v6, v10, v14);
		QR(v3, v7, v11, v15);

		QR(v0, v5, v10, v15);
		QR(v1, v6, v11, v12);
		QR(v2, v7, v8,  v13);
		QR(v3, v4, v9,  v14);
	}
#undef QR

#define ADD(n) v##n = _mm_add_epi32(v##n, _mm_set1_epi32((int) in->d[n]))
	ADD(0);  ADD(1);  ADD(2);  ADD(3);
	ADD(4);  ADD(5);  ADD(6);  ADD(7);
	ADD(8);  ADD(9);  ADD(10); ADD(11);
	         ADD(13); ADD(14); ADD(15);
#undef ADD
	v12 = _mm_add_epi32(v12, _mm_setr_epi32((int) c, (int) (c + 1),
	                                        (int) (c + 2), (int) (c + 3)));

	/* four registers holding word w of blocks 0..3 become four holding
	 * words w..w+3 of one block each, the order they are written in */
#define TRANSPOSE(qa, qb, qc, qd)                              \
	do {                                                   \
		__m128i t0_ = _mm_unpacklo_epi32(qa, qb);      \
		__m128i t1_ = _mm_unpackhi_epi32(qa, qb);      \
		__m128i t2_ = _mm_unpacklo_epi32(qc, qd);      \
		__m128i t3_ = _mm_unpackhi_epi32(qc, qd);      \
		qa = _mm_unpacklo_epi64(t0_, t2_);             \
		qb = _mm_unpackhi_epi64(t0_, t2_);             \
		qc = _mm_unpacklo_epi64(t1_, t3_);             \
		qd = _mm_unpackhi_epi64(t1_, t3_);             \
	} while (0)
	TRANSPOSE(v0,  v1,  v2,  v3);
	TRANSPOSE(v4,  v5,  v6,  v7);
	TRANSPOSE(v8,  v9,  v10, v11);
	TRANSPOSE(v12, v13, v14, v15);
#undef TRANSPOSE

#define ST(j, g, v) _mm_storeu_si128((__m128i *) (out[j].d + (g)), v)
	ST(0, 0, v0);   ST(1, 0, v1);   ST(2, 0, v2);   ST(3, 0, v3);
	ST(0, 4, v4);   ST(1, 4, v5);   ST(2, 4, v6);   ST(3, 4, v7);
	ST(0, 8, v8);   ST(1, 8, v9);   ST(2, 8, v10);  ST(3, 8, v11);
	ST(0, 12, v12); ST(1, 12, v13); ST(2, 12, v14); ST(3, 12, v15);
#undef ST
}

TARGET
static void SIZED(combine)(int rounds, uint8_t *dst, const uint8_t *src,
                           const crypton_chacha_state *in)
{
	block k[4];
	const uint8_t *ks = (const uint8_t *) k;
	int i;

	SIZED(core4)(rounds, k, in);
	for (i = 0; i < 256; i += 16)
		_mm_storeu_si128((__m128i *) (dst + i),
		                 _mm_xor_si128(_mm_loadu_si128((const __m128i *) (src + i)),
		                               _mm_loadu_si128((const __m128i *) (ks + i))));
}

TARGET
static void SIZED(generate)(int rounds, uint8_t *dst, const crypton_chacha_state *in)
{
	block k[4];
	const uint8_t *ks = (const uint8_t *) k;
	int i;

	SIZED(core4)(rounds, k, in);
	for (i = 0; i < 256; i += 16)
		_mm_storeu_si128((__m128i *) (dst + i),
		                 _mm_loadu_si128((const __m128i *) (ks + i)));
}
