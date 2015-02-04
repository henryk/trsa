#ifndef LIBTRSA_H
#define LIBTRSA_H

#include <stdint.h>
#include <gmp.h>

typedef struct trsa_context *trsa_ctx;

extern trsa_ctx trsa_init ();
extern int trsa_fini(trsa_ctx ctx);

extern int trsa_key_generate(trsa_ctx ctx, unsigned int numbits, unsigned int t, unsigned int l);

extern int trsa_share_get(trsa_ctx ctx, unsigned int i, uint8_t **data, size_t *data_length);
extern int trsa_share_set(trsa_ctx ctx, const uint8_t *data, size_t data_length);

extern int trsa_encrypt_generate(trsa_ctx ctx,
		uint8_t *session_key, size_t session_key_length,
		uint8_t *encrypted_session_key, size_t *encrypted_session_key_length);

extern int trsa_decrypt_prepare(trsa_ctx ctx,
		const uint8_t *encrypted_session_key, size_t encrypted_session_key_length,
		uint8_t *challenge, size_t *challenge_length);

extern int trsa_decrypt_partial(trsa_ctx ctx,
		const uint8_t *challenge, size_t challenge_length,
		uint8_t *response, size_t *response_length);

extern int trsa_decrypt_contribute(trsa_ctx ctx,
		const uint8_t *response, size_t response_length);

extern int trsa_decrypt_finish(trsa_ctx ctx,
		uint8_t *session_key, size_t *session_key_length);


// extern int trsa_key_backup(trsa_ctx ctx ...);
extern int trsa_pubkey_get(trsa_ctx ctx, uint8_t *data, size_t *data_length);
extern int trsa_pubkey_set(trsa_ctx ctx, const uint8_t *data, size_t data_length);

extern int trsa_op_pub(trsa_ctx ctx, mpz_t in, mpz_t out);

extern int trsa_op_partial(trsa_ctx ctx, mpz_t in, mpz_t out);
extern int trsa_op_combine_set(trsa_ctx ctx, unsigned int i, mpz_t in);
extern int trsa_op_combine_do(trsa_ctx ctx, mpz_t out);

#endif
