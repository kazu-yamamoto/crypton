#include "crypton_blake2s.h"

void crypton_blake2s_init(blake2s_ctx *ctx, uint32_t hashlen)
{
	_crypton_blake2s_init(ctx, hashlen / 8);
}

void crypton_blake2s_update(blake2s_ctx *ctx, const uint8_t *data, uint32_t len)
{
	_crypton_blake2s_update(ctx, data, len);
}

void crypton_blake2s_finalize(blake2s_ctx *ctx, uint32_t hashlen, uint8_t *out)
{
	_crypton_blake2s_final(ctx, out, hashlen / 8);
}
