#ifndef CRYPTON_RC4_H
# define CRYPTON_RC4_H

struct rc4_ctx
{
	uint8_t state[256];
	uint32_t i;
	uint32_t j;
};

void crypton_rc4_init(uint8_t * key, uint32_t keylen, struct rc4_ctx *ctx);
void crypton_rc4_combine(struct rc4_ctx *ctx, uint8_t *input, uint32_t len, uint8_t *output);

#endif
