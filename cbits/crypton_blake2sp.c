#include "crypton_blake2sp.h"

void crypton_blake2sp_init(blake2sp_ctx *ctx, uint32_t hashlen)
{
	_crypton_blake2sp_init(ctx, hashlen / 8);
}

void crypton_blake2sp_update(blake2sp_ctx *ctx, const uint8_t *data, uint32_t len)
{
	_crypton_blake2sp_update(ctx, data, len);
}

void crypton_blake2sp_finalize(blake2sp_ctx *ctx, uint32_t hashlen, uint8_t *out)
{
	_crypton_blake2sp_final(ctx, out, hashlen / 8);
}
