#include <stdlib.h>
#include <string.h>
#ifdef DEBUG_PRINTF
#include <stdio.h>
#endif /* DEBUG_PRINTF */

#include <gmp.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "buffer.h"
#include "libtrsa.h"

#define PRIME_GENERATION_RETRIES 100
#define DEFAULT_PUBLIC_EXPONENT 65537
#define SECONDARY_SECURITY_PARAMETER 128

#define PBKDF2_ITERATIONS 1000
#define PBKDF2_DIGEST EVP_sha512()
#define MAXIMUM_SESSION_KEY_LENGTH 60000
#define MAXIMUM_UINT16 65535

#define MAGIC_SIZE 8
#define MAGIC_SHARE   "TRSAs\r\n\x00"
#define MAGIC_PUBKEY  "TRSAp\r\n\x00"
#define MAGIC_KEMKEY  "TRSAk\r\n\x00"

/* Public components: t, l, n, e */
#define BUFFER_FORMAT_PUBLIC(ctx) \
	BUFFER_FORMAT_UINT16(ctx->t), \
	BUFFER_FORMAT_UINT16(ctx->l), \
	BUFFER_FORMAT_MPZ(ctx->n), \
	BUFFER_FORMAT_MPZ(ctx->e)

#define BUFFER_FORMAT_MAGIC(m) \
	BUFFER_FORMAT_FIXED_BYTES((const uint8_t*)m, MAGIC_SIZE)

/* Pubkey serialization: magic, public components */
#define BUFFER_FORMAT_PUBKEY(ctx) \
	BUFFER_FORMAT_MAGIC(MAGIC_PUBKEY), \
	BUFFER_FORMAT_PUBLIC(ctx)

/* Share serialization: magic, public components, i, s_i */
#define BUFFER_FORMAT_SHARE(ctx, i, s_i) \
	BUFFER_FORMAT_MAGIC(MAGIC_SHARE), \
	BUFFER_FORMAT_PUBLIC(ctx), \
	BUFFER_FORMAT_UINT16(i), \
	BUFFER_FORMAT_MPZ(s_i)

/* Kemkey serialization (in two parts): magic, session key length, public components; and y */
#define BUFFER_FORMAT_KEMKEY_1(ctx, session_key_length) \
	BUFFER_FORMAT_MAGIC(MAGIC_KEMKEY), \
	BUFFER_FORMAT_UINT16(session_key_length), \
	BUFFER_FORMAT_PUBLIC(ctx)

#define BUFFER_FORMAT_KEMKEY_2(y) \
	BUFFER_FORMAT_MPZ(y)

/* Challenge serialization: challenge */
#define BUFFER_FORMAT_CHALLENGE(challenge) \
	BUFFER_FORMAT_MPZ_ASCII(challenge)

/* Response serialization: i : x_partial */
#define BUFFER_FORMAT_RESPONSE(i, x_partial) \
	BUFFER_FORMAT_UINT16_ASCII(i), \
	BUFFER_FORMAT_FIXED_BYTES((const uint8_t*)":", 1), \
	BUFFER_FORMAT_MPZ_ASCII(x_partial)


struct trsa_context {
	mpz_t p, q, n, e, d;
	mpz_t *s, my_s,  r, y_challenge;
	uint16_t t, l, my_i,  decrypt_length;

	struct part {
		uint16_t i;
		mpz_t x_;
		struct part *next;
		struct part *combine_next;
	} *part_head;
	size_t part_count;

	uint32_t have;
	uint32_t state;
};

#define CTX_PUBLIC        (1L<<0)   /* Note: Clearing CTX_PUBLIC implies clearing everything (CTX_ALL) */
#define CTX_PRIVATE       (1L<<1)
#define CTX_SHARES        (1L<<2)
#define CTX_MY_SHARE      (1L<<3)
#define CTX_CHALLENGE     (1L<<4)   /* Note: Clearing CTX_CHALLENGE also clears CTX_PARTIALS */
#define CTX_PARTIALS      (1L<<5)

#define CTX_ALL           (CTX_PUBLIC|CTX_PRIVATE|CTX_SHARES|CTX_MY_SHARE|CTX_CHALLENGE|CTX_PARTIALS)

#define STATE_NONE        (1L<<0)
#define STATE_DEC_PREP    (1L<<1)
#define STATE_DEC_READY   (1L<<2)

#define METHOD_START(ctx, ...) do { \
	if(ctx_require(ctx, (struct ctx_require_arguments){__VA_ARGS__}) < 0) \
		return -1; \
} while(0)

#define METHOD_FINISH(ctx, retval, ...) ctx_provide(ctx, retval, (struct ctx_provide_arguments){__VA_ARGS__})

#define START(...)  METHOD_START(ctx, __VA_ARGS__); int retval = -1
#define FINISH(...) return METHOD_FINISH(ctx, retval, __VA_ARGS__)

#define ABORT_IF_ERROR( exp ) do { int r = (exp); if(r<0){retval=r; goto abort;} } while(0)
#define ABORT_IF( exp ) do { if( exp ) { goto abort; } } while(0)
#define ABORT_IF_INVALID( parts ) ABORT_IF_ERROR( ctx_verify(ctx, parts) )

struct ctx_require_arguments {
	uint32_t need, clear;
	uint32_t need_state;
};

struct ctx_provide_arguments {
	uint32_t provide;
	uint32_t state, state_success, state_error;
	uint32_t clear;
};

static int ctx_require(trsa_ctx ctx, struct ctx_require_arguments args);
static int ctx_provide(trsa_ctx ctx, int retval, struct ctx_provide_arguments args);
static int ctx_clear(trsa_ctx ctx, uint32_t clear);
static int ctx_verify(trsa_ctx ctx, uint32_t parts);

#define BITMAP_SIZE(n) ( (n+7)/8 )
#define BITMAP_BYTE_INDEX(i) ((i)/8)
#define BITMAP_BIT_INDEX(i) ((i)%8)
#define BITMAP_SET(x, i) x[ BITMAP_BYTE_INDEX(i) ] |= 1L<<BITMAP_BIT_INDEX(i)
#define BITMAP_CLEAR(x, i) x[ BITMAP_BYTE_INDEX(i) ] &= ~(1L<<BITMAP_BIT_INDEX(i))
#define BITMAP_ISSET(x, i) (x[ BITMAP_BYTE_INDEX(i) ] & 1L<<BITMAP_BIT_INDEX(i))

trsa_ctx trsa_init ()
{
	struct trsa_context *ctx = calloc(1, sizeof(*ctx));
	if(!ctx) {
		return NULL;
	}

	mpz_inits(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, ctx->my_s, ctx->r, ctx->y_challenge, NULL);

	ctx->state = STATE_NONE;

	return ctx;
}

int trsa_fini(trsa_ctx ctx)
{
	if(!ctx) {
		return -1;
	}

	/* FIXME: Check if cleaning up actually destroys memory */
	ctx_clear(ctx, CTX_ALL);
	mpz_clears(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, ctx->my_s, ctx->r, ctx->y_challenge, NULL);
	free(ctx);

	return 0;
}

static unsigned long FIRST_PRIMES[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
		31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
		107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
		181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
		263, 269, 271, 277, 281, 283, 293, 307};

static int accept_prime(mpz_t p, unsigned int t)
{
	int retval = 0;
	mpz_t minusonehalf;
	mpz_init(minusonehalf);

	ABORT_IF( mpz_probab_prime_p(p, 25) == 0);

	mpz_sub_ui(minusonehalf, p, 1);
	mpz_divexact_ui(minusonehalf, minusonehalf, 2);

	for(int i=0; i<sizeof(FIRST_PRIMES)/sizeof(FIRST_PRIMES[0]); i++) {
		if(FIRST_PRIMES[i] >= 3*t*t) {
			break;
		}
		ABORT_IF( mpz_fdiv_ui(minusonehalf, FIRST_PRIMES[i]) == 0);
	}

	// When we have exhausted FIRST_PRIMES, just continue by adding 2
	// There's a lot of unnecessary work (since not all odd numbers are primes)
	// but it's functionally harmless (since all primes greater 2 are odd)
	for(unsigned long p = FIRST_PRIMES[sizeof(FIRST_PRIMES)/sizeof(FIRST_PRIMES[0]) - 1]; p<3*t*t; p+=2) {
		ABORT_IF( mpz_fdiv_ui(minusonehalf, p) == 0);
	}

	retval = 1;

abort:
	mpz_clear(minusonehalf);
	return retval;
}

static void evaluate_poly(mpz_t rop, mpz_t *c, unsigned int order, unsigned long int x)
{
	mpz_t tmp;
	mpz_init(tmp);

	mpz_set_ui(rop, 0);

	for(int i=0; i<=order; i++) {
		mpz_set_ui(tmp, x);
		mpz_pow_ui(tmp, tmp, i);
		mpz_addmul(rop, c[i], tmp);
	}

	mpz_clear(tmp);
}

/*
 * Generate b random bits and put them into out
 */
static int random_bits(mpz_t out, size_t b)
{
	uint8_t *buffer = NULL;
	int retval = -1;
	mpz_set_ui(out, 0);

	uint8_t final_mask = 0xFF;
	size_t full_byte_count = b / 8;
	if(b % 8) {
		full_byte_count ++;
		final_mask = ~((~0L)<<(b%8));
	}

	buffer = malloc(full_byte_count);
	ABORT_IF(!buffer);

#ifdef DEBUG_MAKE_RNG_DETERMINISTIC
	static volatile uint32_t state = 0;
	for(size_t i=0; i<full_byte_count; i++) {
		buffer[i] = (state>>16) & 0xff;
		state = state * 1103515245L + 12345;
	}
#else
	ABORT_IF( RAND_bytes(buffer, full_byte_count) != 1 );
#endif

	buffer[full_byte_count-1] &= final_mask;

	mpz_import(out, full_byte_count, -1, 1, -1, 0, buffer);

	retval = 0;

abort:
	if(buffer) {
		OPENSSL_cleanse(buffer, full_byte_count);
		free(buffer);
	}

	return retval;
}

/*
 * Put random x with 0 <= x < m into out
 * Based on http://crypto.stackexchange.com/a/7998/2723
 */
static int random_number(mpz_t out, mpz_t m)
{
	int retval = -1;
	mpz_t t;

	/* this is the minimum value for u, it may be bigger.
	 * bigger u consumes slightly more entropy but reduces the
	 * average loop count below
	 */
	size_t u = mpz_sizeinbase(m, 2);

	/* round up u to a multiple of 8, since random_bits()
	 * internally operates on bytes anyway
	 */
	if(u%8 != 0) {
		u += 8 - (u%8);
	}

	mpz_init_set_ui(t, 1);
	mpz_mul_2exp(t, t, u);

	mpz_fdiv_q(t, t, m);
	mpz_mul(t, t, m);

#ifdef DEBUG_PRINTF
	printf("R m: "); mpz_out_str(stdout, 10, m); printf("\n");
	printf("R u: %zi\n", u);
	printf("R t: "); mpz_out_str(stdout, 10, t); printf("\n");
#endif /* DEBUG_PRINTF */

	do {
		ABORT_IF( random_bits(out, u) < 0 );
#ifdef DEBUG_PRINTF
		printf("R x: "); mpz_out_str(stdout, 10, out); printf("\n");
#endif /* DEBUG_PRINTF */
	} while(mpz_cmp(out, t) >= 0);

	mpz_mod(out, out, m);
	retval = 0;

#ifdef DEBUG_PRINTF
	printf("R r: "); mpz_out_str(stdout, 10, out); printf("\n");
#endif /* DEBUG_PRINTF */

abort:
	mpz_clear(t);
	return retval;
}

int trsa_key_generate(trsa_ctx ctx, unsigned int numbits, unsigned int t, unsigned int l)
{
	START(.clear=CTX_ALL);

	unsigned int qlength = numbits/2;
	unsigned int plength = numbits - qlength;
	mpz_t phi_n, pminus, qminus, delta, c_max, tmp, tmp2;
	mpz_t *c = NULL;

	mpz_inits(phi_n, pminus, qminus, delta, c_max, tmp, tmp2, NULL);

	ABORT_IF(t < 1 || t > MAXIMUM_UINT16);
	ABORT_IF(l < 1 || l > MAXIMUM_UINT16);
	ABORT_IF(t+1 > l);
	ABORT_IF(numbits < 0);

	ctx->t = t;
	ctx->l = l;

	ABORT_IF_ERROR( random_bits(ctx->p, plength) );
	ABORT_IF_ERROR( random_bits(ctx->q, qlength) );

	// Set least and most significant bits to get an odd number of maximal bit length
	mpz_setbit(ctx->p, 0);
	mpz_setbit(ctx->p, plength-1);

	mpz_setbit(ctx->q, 0);
	mpz_setbit(ctx->q, qlength-1);


	int retries = PRIME_GENERATION_RETRIES;
	do {
		mpz_nextprime(ctx->p, ctx->p);

		if(accept_prime(ctx->p, t)) {
			break;
		}

	} while(--retries > 0);

	ABORT_IF(retries <= 0);

	retries = PRIME_GENERATION_RETRIES;
	do {
		mpz_nextprime(ctx->q, ctx->q);

		if(accept_prime(ctx->q, t) && mpz_cmp(ctx->p, ctx->q) != 0) {
			break;
		}

	} while(--retries > 0);

	ABORT_IF(retries <= 0);

	mpz_sub_ui(pminus, ctx->p, 1);
	mpz_sub_ui(qminus, ctx->q, 1);

	mpz_mul(ctx->n, ctx->p, ctx->q);
	mpz_mul(phi_n, pminus, qminus);

	mpz_set_ui(ctx->e, DEFAULT_PUBLIC_EXPONENT);

	retries = PRIME_GENERATION_RETRIES;
	do {
		// tmp = GCD(e, 4*DELTA^2)
		mpz_fac_ui(delta, l);
		mpz_mul(tmp2, delta, delta);
		mpz_mul_ui(tmp2, tmp2, 4);
		mpz_gcd(tmp, ctx->e, tmp2);

		// tmp2 = GCD(e, phi_n)
		mpz_gcd(tmp2, ctx->e, phi_n);

		if(mpz_cmp_ui(tmp, 1) == 0 && mpz_cmp_ui(tmp2, 1) == 0) {
			break;
		}

		mpz_nextprime(ctx->e, ctx->e);
	} while(--retries > 0);

	ABORT_IF(retries <= 0);

	mpz_invert(ctx->d, ctx->e, phi_n);

	mpz_set(c_max, delta);
	mpz_mul(c_max, c_max, ctx->n);
	mpz_mul_2exp(c_max, c_max, t);
	mpz_mul_2exp(c_max, c_max, SECONDARY_SECURITY_PARAMETER);

	c = calloc(t+1, sizeof(*c));
	ABORT_IF(!c);

	mpz_init(c[0]);
	for(int i=1; i<=t; i++) {
		mpz_init(c[i]);
	}

	mpz_set(c[0], ctx->d);
	for(int i=1; i<=t; i++) {
		if(random_number(c[i], c_max) < 0) {
			goto abort;
		}
	}

	ctx->s = calloc(l, sizeof(*ctx->s));
	ABORT_IF(!ctx->s);

	for(int i=0; i<l; i++) {
		mpz_init(ctx->s[i]);
	}

	for(int i=1; i<=l; i++) {
		evaluate_poly(ctx->s[i-1], c, t, i);
	}

	// FIXME Generate verification values

#ifdef DEBUG_PRINTF
	printf("G q: "); mpz_out_str(stdout, 10, ctx->q); printf("\n");
	printf("G p: "); mpz_out_str(stdout, 10, ctx->p); printf("\n");
	printf("G n: "); mpz_out_str(stdout, 10, ctx->n); printf("\n");
	printf("G phi_n: "); mpz_out_str(stdout, 10, phi_n); printf("\n");
	printf("G e: "); mpz_out_str(stdout, 10, ctx->e); printf("\n");
	printf("G d: "); mpz_out_str(stdout, 10, ctx->d); printf("\n");
	for(int i=0; i<=t; i++) {
		printf("G c_%i: ", i); mpz_out_str(stdout, 10, c[i]); printf("\n");
	}
	for(int i=1; i<=l; i++) {
		printf("G s_%i: ", i); mpz_out_str(stdout, 10, ctx->s[i-1]); printf("\n");
	}
#endif /* DEBUG_PRINTF */

	retval = 0;

abort:
	mpz_clears(phi_n, pminus, qminus, delta, c_max, tmp, tmp2, NULL);
	if(c != NULL) {
		for(int i=0; i<=t; i++) {
			mpz_clear(c[i]);
		}
	}
	free(c);

	FINISH(CTX_PUBLIC | CTX_PRIVATE | CTX_SHARES);
}

int trsa_share_get(trsa_ctx ctx, unsigned int i, uint8_t **data, size_t *data_length) {
	START(.need = CTX_PUBLIC | CTX_SHARES);

	if(!data || !data_length) {
		return -1;
	}

	if(i < 1 || i > ctx->l) {
		return -1;
	}

	uint16_t i16 = i;

	buffer_t buffer = buffer_alloc_put(
		BUFFER_FORMAT_SHARE(ctx, i16, ctx->s[i-1])
	);
	ABORT_IF(!buffer);

	buffer_give_up(&buffer, data, data_length);
	retval = 0;

abort:
	buffer_free(buffer);

	FINISH(0);
}

int trsa_share_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) {
	START(.clear = CTX_PUBLIC | CTX_MY_SHARE);

	if(!data || !data_length) {
		return -1;
	}

	// Read in public parameters, followed by private share parameters my_i, ctx->my_s

	buffer_t buffer = buffer_init(data, data_length);
	ABORT_IF(!buffer);

	ABORT_IF_ERROR( buffer_get(buffer,
		BUFFER_FORMAT_SHARE(ctx, ctx->my_i, ctx->my_s)
	));
	ABORT_IF_INVALID( CTX_PUBLIC | CTX_MY_SHARE );

	retval = 0;

abort:
	buffer_free(buffer);

	FINISH(CTX_PUBLIC | CTX_MY_SHARE);
}

/* Common control flow between trsa_encrypt_generate() and trsa_decrypt_finish():
 * 1. Dump x into x_buffer
 * 2. Dump magic, pubkey, session_key_length into buffer
 * 3. use buffer as salt and x_buffer as input to KDF, generate session_key output
 *
 * INTERNAL USE: no parameters are checked or freed!
 */
static int session_key_common(trsa_ctx ctx,
		buffer_t *buffer, buffer_t *x_buffer, mpz_t *x,
		uint8_t *session_key, size_t session_key_length)
{
	*x_buffer = buffer_alloc_put( BUFFER_FORMAT_MPZP(x) );
	if(!*x_buffer) return -1;

	if(session_key_length > MAXIMUM_SESSION_KEY_LENGTH) {
		// The OpenSSL API uses int as a length type, ward against overflows
		return -1;
	}
	uint16_t s = session_key_length;

	*buffer = buffer_alloc_put(
			BUFFER_FORMAT_KEMKEY_1(ctx, s)
	);
	if(!*buffer) return -1;

	int r = PKCS5_PBKDF2_HMAC((char*)((*x_buffer)->d), (*x_buffer)->p,
			(*buffer)->d, (*buffer)->p,
			PBKDF2_ITERATIONS, PBKDF2_DIGEST,
			session_key_length, session_key);
	if(!r) return -1;

	return 0;
}

int trsa_encrypt_generate(trsa_ctx ctx,
		uint8_t *session_key, size_t session_key_length,
		uint8_t **encrypted_session_key, size_t *encrypted_session_key_length) {

	START(.need = CTX_PUBLIC);

	if(!session_key || !encrypted_session_key || !encrypted_session_key_length) {
		return -1;
	}

	mpz_t x, y, tmp;
	buffer_t x_buffer = NULL, buffer = NULL;

	mpz_inits(x, y, tmp, NULL);

	// 1. Generate random x with GCD(x, n) == 1
	do {
		ABORT_IF_ERROR( random_number(x, ctx->n) );

		// FIXME Insecure?
		mpz_gcd(tmp, x, ctx->n);
	} while(mpz_cmp_ui(tmp, 1) != 0);

	// 2. Encrypt (public operation) x to yield y
	ABORT_IF_ERROR( trsa_op_pub(ctx, x, y) );

	// 3. Dump magic || pubkey || session_key_length into buffer,  dump x into x_buffer
	// 4. use buffer as salt and x_buffer as input to KDF, generate session_key output
	ABORT_IF_ERROR( session_key_common(ctx, &buffer, &x_buffer, &x, session_key, session_key_length) );

	// 5. Append y to buffer (is now magic || pubkey || y) and output encrypted_session_key
	ABORT_IF_ERROR( buffer_put(buffer,
		BUFFER_FORMAT_KEMKEY_2(y)
	));

	buffer_give_up(&buffer, encrypted_session_key, encrypted_session_key_length);
	retval = 0;

abort:
	mpz_clears(x, y, tmp, NULL);
	buffer_free(x_buffer);
	buffer_free(buffer);

	FINISH(0);
}

static int mask_apply(trsa_ctx ctx, mpz_t *r, mpz_t *y)
{
	if(!ctx || !r || !y) {
		return -1;
	}

	int retval = -1;
	mpz_t tmp;
	mpz_init(tmp);

	do {
		ABORT_IF( random_number(*r, ctx->n) < 0 );

		// FIXME Insecure?
		mpz_gcd(tmp, *r, ctx->n);
	} while(mpz_cmp_ui(tmp, 1) != 0);

	mpz_powm_sec(tmp, *r, ctx->e, ctx->n);
	mpz_mul(*y, *y, tmp);
	mpz_mod(*y, *y, ctx->n);

	retval = 0;

abort:
	mpz_clear(tmp);
	return retval;
}

static int mask_remove(trsa_ctx ctx, mpz_t *r, mpz_t *x)
{
	if(!ctx || !r || !x) {
		return -1;
	}

	int retval = -1;
	mpz_t tmp;
	mpz_init(tmp);

	// FIXME Insecure?
	mpz_gcd(tmp, *r, ctx->n);
	ABORT_IF(mpz_cmp_ui(tmp, 1) != 0);

	// FIXME Insecure?
	mpz_invert(tmp, *r, ctx->n);
	mpz_mul(*x, *x, tmp);
	mpz_mod(*x, *x, ctx->n);

	retval = 0;

abort:
	mpz_clear(tmp);
	return retval;

}

int trsa_decrypt_prepare(trsa_ctx ctx,
		const uint8_t *encrypted_session_key, size_t encrypted_session_key_length,
		uint8_t **challenge, size_t *challenge_length) {

	START(.clear = CTX_PUBLIC | CTX_CHALLENGE);

	if(!encrypted_session_key || !challenge || !challenge_length) {
		return -1;
	}

	mpz_t y;
	buffer_t buffer = NULL, output = NULL;

	mpz_init(y);

	buffer = buffer_init(encrypted_session_key, encrypted_session_key_length);
	ABORT_IF(!buffer);

	// 1. Verify and read encrypted_session_key, yielding pubkey, y and session_key_length

	ABORT_IF_ERROR( buffer_get(buffer,
		BUFFER_FORMAT_KEMKEY_1(ctx, ctx->decrypt_length),
		BUFFER_FORMAT_KEMKEY_2(y)
	));
	ABORT_IF_INVALID( CTX_PUBLIC );

#ifdef DEBUG_PRINTF
	printf("D y: "); mpz_out_str(stdout, 10, y); printf("\n");
#endif /* DEBUG_PRINTF */

	// 2. Apply masking
	ABORT_IF_ERROR( mask_apply(ctx, &ctx->r, &y) );

	// 3. Record parameters in context

	mpz_set(ctx->y_challenge, y);

	// 4. Generate and output challenge
	output = buffer_alloc_put(BUFFER_FORMAT_CHALLENGE(ctx->y_challenge));
	ABORT_IF(!output);

	buffer_give_up(&output, challenge, challenge_length);
	retval = 0;

#ifdef DEBUG_PRINTF
	printf("D r: "); mpz_out_str(stdout, 10, ctx->r); printf("\n");
	printf("D y_challenge: "); mpz_out_str(stdout, 10, ctx->y_challenge); printf("\n");
#endif /* DEBUG_PRINTF */

abort:
	mpz_clear(y);
	buffer_free(buffer);
	buffer_free(output);

	FINISH(CTX_PUBLIC | CTX_CHALLENGE, .state=STATE_DEC_PREP);
}

int trsa_decrypt_partial(trsa_ctx ctx,
		const uint8_t *challenge, size_t challenge_length,
		uint8_t **response, size_t *response_length) {

	START(.need = CTX_PUBLIC | CTX_MY_SHARE);

	if(!challenge || !response || !response_length) {
		return -1;
	}

	mpz_t y_challenge, x_partial;
	buffer_t in = NULL, out = NULL;

	mpz_inits(y_challenge, x_partial, NULL);
	in = buffer_init(challenge, challenge_length);
	ABORT_IF(!in);

	// 1. Read challenge
	ABORT_IF_ERROR( buffer_get(in, BUFFER_FORMAT_CHALLENGE(y_challenge)) );

	// 2. Perform partial computation
	ABORT_IF_ERROR( trsa_op_partial(ctx, y_challenge, x_partial) );

	// 3. Output response  i || x_partial
	out = buffer_alloc_put(BUFFER_FORMAT_RESPONSE(ctx->my_i, x_partial));
	ABORT_IF(!out);

	buffer_give_up(&out, response, response_length);
	retval = 0;

abort:
	mpz_clears(y_challenge, x_partial, NULL);
	buffer_free(in);
	buffer_free(out);

	FINISH(0);
}

int trsa_decrypt_contribute(trsa_ctx ctx,
		const uint8_t *response, size_t response_length) {

	START(.need_state=STATE_DEC_PREP | STATE_DEC_READY);

	if(!response) {
		return -1;
	}

	uint16_t i;
	mpz_t x_partial;
	buffer_t buffer = NULL;

	mpz_init(x_partial);
	buffer = buffer_init(response, response_length);
	ABORT_IF(!buffer);

	// 1. Read response i || x_partial
	ABORT_IF_ERROR( buffer_get(buffer, BUFFER_FORMAT_RESPONSE(i, x_partial)) );

	// 2. Set in context
	retval = trsa_op_combine_set(ctx, i, x_partial);

abort:
	mpz_clear(x_partial);
	buffer_free(buffer);

	FINISH(.state_success=STATE_DEC_READY);
}

int trsa_decrypt_finish(trsa_ctx ctx,
		uint8_t *session_key, size_t session_key_length) {

	START(.need = CTX_PUBLIC | CTX_CHALLENGE, .need_state=STATE_DEC_READY);

	if(!session_key) {
		return -1;
	}

	mpz_t x;
	buffer_t x_buffer = NULL, buffer = NULL;

	mpz_init(x);

	ABORT_IF( ctx->decrypt_length != session_key_length );

	// 1. Execute combine operation, yielding x
	ABORT_IF_ERROR( trsa_op_combine_do(ctx, ctx->y_challenge, x) );

	// 2. Remove masking
	ABORT_IF_ERROR( mask_remove(ctx, &ctx->r, &x) );

	// 3. dump magic || pubkey || session_key_length into buffer,  x into x_buffer
	// 4. use buffer as salt and x_buffer as input to KDF, generate session_key output
	ABORT_IF_ERROR( session_key_common(ctx, &buffer, &x_buffer, &x, session_key, session_key_length) );

	retval = 0;

abort:
	mpz_clear(x);
	buffer_free(x_buffer);
	buffer_free(buffer);

	FINISH(.state=STATE_NONE, .clear = CTX_CHALLENGE | CTX_PARTIALS);
}

int trsa_pubkey_get(trsa_ctx ctx, uint8_t **data, size_t *data_length) {
	START(.need = CTX_PUBLIC);

	if(!data || !data_length) {
		return -1;
	}

	// Write out public parameters
	buffer_t buffer = buffer_alloc_put(BUFFER_FORMAT_PUBKEY(ctx));
	ABORT_IF(!buffer);

	buffer_give_up(&buffer, data, data_length);
	retval = 0;

abort:
	buffer_free(buffer);

	FINISH(0);
}

int trsa_pubkey_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) {
	START(.clear = CTX_PUBLIC);

	if(!data || !data_length) {
		return -1;
	}

	// Read in public parameters

	buffer_t buffer = buffer_init(data, data_length);
	ABORT_IF(!buffer);

	ABORT_IF_ERROR( buffer_get(buffer, BUFFER_FORMAT_PUBKEY(ctx)) );
	ABORT_IF_INVALID( CTX_PUBLIC );

	retval = 0;

abort:
	buffer_free(buffer);

	FINISH(CTX_PUBLIC);
}


int trsa_op_pub(trsa_ctx ctx, mpz_t in, mpz_t out)
{
	METHOD_START(ctx, .need = CTX_PUBLIC);

	mpz_powm_sec(out, in, ctx->e, ctx->n);

#ifdef DEBUG_PRINTF
	printf("pub in: "); mpz_out_str(stdout, 10, in); printf("\n");
	printf("pub out: "); mpz_out_str(stdout, 10, out); printf("\n");
#endif /* DEBUG_PRINTF */

	return METHOD_FINISH(ctx, 0, 0);
}

int trsa_op_partial(trsa_ctx ctx, mpz_t in, mpz_t out)
{
	METHOD_START(ctx, .need = CTX_PUBLIC | CTX_MY_SHARE);

	mpz_t exponent;
	mpz_init(exponent);

	// exponent = (2 delta)
	mpz_fac_ui(exponent, ctx->l);
	mpz_mul_ui(exponent, exponent, 2);

	mpz_powm_sec(out, in, exponent, ctx->n);
	mpz_powm_sec(out, out, ctx->my_s, ctx->n);

	mpz_clear(exponent);

#ifdef DEBUG_PRINTF
	printf("part %i in: ", ctx->my_i); mpz_out_str(stdout, 10, in); printf("\n");
	printf("part %i out: ", ctx->my_i); mpz_out_str(stdout, 10, out); printf("\n");
#endif /* DEBUG_PRINTF */

	return METHOD_FINISH(ctx, 0, 0);
}

static int parts_unique_count(trsa_ctx ctx)
{
	if(!ctx) {
		return -1;
	}

	uint8_t *have = calloc(1, BITMAP_SIZE(ctx->l));
	if(!have) {
		return -1;
	}

	struct part *p = ctx->part_head;
	while(p) {
		BITMAP_SET(have, p->i-1);
		p = p->next;
	}

	int retval = 0;
	for(int i=0; i<BITMAP_SIZE(ctx->l); i++) {
		retval += __builtin_popcount(have[i]);
	}

	free(have);
	return retval;
}

int trsa_op_combine_set(trsa_ctx ctx, unsigned int i, mpz_t in)
{
	START(0);
	uint32_t ok_mask = 0;
	struct part *tmp = NULL;

	ABORT_IF(i < 1 || i > ctx->l);

	tmp = calloc(1, sizeof(*tmp));
	ABORT_IF(!tmp);

	mpz_init(tmp->x_);

	mpz_set(tmp->x_, in);
	tmp->i = i;
	tmp->next = ctx->part_head;
	ctx->part_head = tmp;
	ctx->part_count++;
	retval = 0;

	int count = parts_unique_count(ctx);
	if(count > ctx->t) {
		retval = 1;
		ok_mask = CTX_PARTIALS;
	}

abort:
	if(retval < 0) {
		if(tmp != NULL) {
			mpz_clear(tmp->x_);
		}
		free(tmp);
	}
	FINISH(ok_mask);
}

static void lambda_S0j(mpz_t out, struct part *p_head, int l, int j)
{
	mpz_fac_ui(out, l);

	for(struct part *p = p_head; p; p = p->combine_next) {
		if(p->i == j) continue;
#ifdef DEBUG_PRINTF
		printf("do %i\n", p->i);
#endif /* DEBUG_PRINTF */
		mpz_mul_ui(out, out, p->i);
	}
	for(struct part *p = p_head; p; p = p->combine_next) {
		if(p->i == j) continue;
		if(p->i<j) {
			mpz_divexact_ui(out, out, j-p->i);
			mpz_neg(out, out);
		} else {
			mpz_divexact_ui(out, out, p->i-j);
		}
	}
#ifdef DEBUG_PRINTF
	printf("lambda(%i): ", j); mpz_out_str(stdout, 10, out); printf("\n");
#endif /* DEBUG_PRINTF */
}

struct permutation_state {
	size_t count, pos, last;
	unsigned int last_set:1;
	int count_selected, n, count_unique;
	struct p_pointer {
		struct part *p;
		size_t prev;
		unsigned int prev_set:1;
	} *items;
	uint8_t *bitmap;
};

int parts_permutation_clear_state(struct permutation_state *pstate)
{
	if(pstate) {
		free(pstate->items);
		free(pstate->bitmap);
	}
	free(pstate);
	return 0;
}

static void append_item(struct permutation_state *state, size_t pos)
{
#ifdef DEBUG_PRINTF
	printf("P append %i (%zi)\n", state->items[pos].p->i, pos);
#endif
	if(BITMAP_ISSET(state->bitmap, state->items[pos].p->i)) {
		return;
	}
	state->items[pos].prev = state->last;
	state->items[pos].prev_set = state->last_set;
	state->last = pos;
	state->last_set = 1;
	if(!BITMAP_ISSET(state->bitmap, state->items[pos].p->i)) {
		state->count_unique++;
	}
	BITMAP_SET(state->bitmap, state->items[pos].p->i);
	state->count_selected++;
}

static void remove_item(struct permutation_state *state)
{
	if(!state->last_set) {
		return;
	}
	size_t pos = state->last;
#ifdef DEBUG_PRINTF
	printf("P remove %i (%zi)\n", state->items[pos].p->i, pos);
#endif
	state->last = state->items[pos].prev;
	state->last_set = state->items[pos].prev_set;
	if(BITMAP_ISSET(state->bitmap, state->items[pos].p->i)) {
		state->count_unique--;
	}
	BITMAP_CLEAR(state->bitmap, state->items[pos].p->i);
	state->count_selected--;
}

int parts_permutation_next(struct permutation_state *state, struct part **out)
{
	if(!state || !out) {
		return -1;
	}

	int accept = 0;
	while(!accept) {
		for(; state->pos < state->count; state->pos++) {
			if(state->count_selected >= state->n) {
				break;
			}

			append_item(state, state->pos);

#ifdef DEBUG_PRINTF
			{
				printf("P permutation now:");
				size_t tmp = state->last;
				int tmp_set = state->last_set;
				while(tmp_set) {
					printf(" %i", state->items[tmp].p->i);
					tmp_set = state->items[tmp].prev_set;
					tmp = state->items[tmp].prev;
				};
				printf("\n");
			}
#endif
		}
		accept = state->count_unique == state->n;
		if(!accept) {
			/* Remove last item and retry by appending one further down. If last item
			 * in origin list was tried: try second to last. */
			remove_item(state);
		}
	}

	{
		*out = NULL;
		size_t tmp = state->last;
		int tmp_set = state->last_set;
		while(tmp_set) {
			state->items[tmp].p->combine_next = *out;
			*out = state->items[tmp].p;
			tmp_set = state->items[tmp].prev_set;
			tmp = state->items[tmp].prev;
		}
	}

	return 0;
}

int parts_permutation_first(struct part *head, int n, size_t part_count,
		struct permutation_state **pstate, struct part **out)
{
	if(!head || !pstate || !out) {
		return -1;
	}
	if(*pstate) {
		parts_permutation_clear_state(*pstate);
		*pstate = NULL;
	}

	struct part *h = head;

	// FIXME Overflows galore
	*pstate = calloc(1, sizeof(**pstate));
	if(!*pstate) {
		return -1;
	}
	(*pstate)->items = calloc(part_count, sizeof(*((*pstate)->items)));
	if(!(*pstate)->items) {
		free(*pstate);
		*pstate = NULL;
		return -1;
	}
	(*pstate)->bitmap = calloc( 1, BITMAP_SIZE(part_count) );
	if(!(*pstate)->bitmap) {
		free((*pstate)->items);
		free(*pstate);
		*pstate = NULL;
		return -1;
	}

	struct permutation_state *state = *pstate;
	state->count = part_count;
	state->n = n;

	h = head;
	size_t i = 0;
	while(h) {
		state->items[i].p = h;
		h = h->next;
		i++;
	}

	return parts_permutation_next(state, out);
}

int trsa_op_combine_do(trsa_ctx ctx, mpz_t in, mpz_t out)
{
	START(.need = CTX_PUBLIC | CTX_PARTIALS);

	mpz_t a, b, w, tmp;
	mpz_inits(a, b, w, tmp, NULL);
	struct permutation_state *pstate = NULL;

	mpz_set_ui(w, 1);

	struct part *p = NULL;
	ABORT_IF_ERROR( parts_permutation_first(ctx->part_head, ctx->t+1, ctx->part_count, &pstate, &p) );

	struct part *p_first = p;
	while(p) {
		lambda_S0j(tmp, p_first, ctx->l, p->i);
		mpz_mul_ui(tmp, tmp, 2);

#ifdef DEBUG_PRINTF
		printf("C base: "); mpz_out_str(stdout, 10, p->x_); printf("\n");
		printf("C exp: "); mpz_out_str(stdout, 10, tmp); printf("\n");
		printf("C mod: "); mpz_out_str(stdout, 10, ctx->n); printf("\n");
#endif /* DEBUG_PRINTF */

		// TODO Insecure?
		mpz_powm(tmp, p->x_, tmp, ctx->n);
		mpz_mul(w, w, tmp);
		mpz_mod(w, w, ctx->n);

		p = p->combine_next;
	}

	mpz_fac_ui(tmp, ctx->l);
	mpz_pow_ui(tmp, tmp, 2);
	mpz_mul_ui(tmp, tmp, 4);

	// TODO Insecure?
	mpz_gcdext(tmp, a, b, tmp, ctx->e);
	ABORT_IF(mpz_cmp_ui(tmp, 1) != 0);

	// TODO Insecure?
	mpz_powm(out, w, a, ctx->n);
	mpz_powm(tmp, in, b, ctx->n);
	mpz_mul(out, out, tmp);
	mpz_mod(out, out, ctx->n);

#ifdef DEBUG_PRINTF
	printf("C a: "); mpz_out_str(stdout, 10, a); printf("\n");
	printf("C b: "); mpz_out_str(stdout, 10, b); printf("\n");
	printf("C w: "); mpz_out_str(stdout, 10, w); printf("\n");
	printf("C out: "); mpz_out_str(stdout, 10, out); printf("\n");
#endif /* DEBUG_PRINTF */

	retval = 0;

abort:
	mpz_clears(a, b, w, tmp, NULL);
	parts_permutation_clear_state(pstate);

	FINISH(0, .clear = CTX_PARTIALS);
}

static int ctx_clear(trsa_ctx ctx, uint32_t clear)
{
	if(!ctx) {
		return -1;
	}

	/* Clearing CTX_PUBLIC implies clearing everything */
	if(clear & CTX_PUBLIC) clear |= CTX_ALL;

	/* Clearing CTX_CHALLENGE also clears CTX_PARTIALS */
	if(clear & CTX_CHALLENGE) clear |= CTX_PARTIALS;

	uint16_t l_saved = ctx->l;
	if(clear & CTX_PUBLIC) {
		mpz_set_ui(ctx->n, 0);
		mpz_set_ui(ctx->e, 0);
		ctx->l = 0;
		ctx->t = 0;
	}

	if(clear & CTX_PRIVATE) {
		mpz_set_ui(ctx->p, 0);
		mpz_set_ui(ctx->q, 0);
		mpz_set_ui(ctx->d, 0);
	}

	if(clear & CTX_SHARES) {
		if(ctx->s != NULL) {
			for(int i=0; i<l_saved; i++) {
				mpz_clear(ctx->s[i]);
			}
			free(ctx->s);
		}
		ctx->s = NULL;
	}

	if(clear & CTX_PARTIALS) {
		while(ctx->part_head != NULL) {
			mpz_clear(ctx->part_head->x_);
			struct part *tmp = ctx->part_head->next;
			free(ctx->part_head);
			ctx->part_head = tmp;
		}
		ctx->part_count = 0;
	}

	if(clear & CTX_CHALLENGE) {
		mpz_set_ui(ctx->r, 0);
		mpz_set_ui(ctx->y_challenge, 0);
	}

	if(clear & CTX_MY_SHARE) {
		mpz_set_ui(ctx->my_s, 0);
		ctx->my_i = 0;
	}

	ctx->have &= ~clear;
	return 0;
}


static int ctx_require(trsa_ctx ctx, struct ctx_require_arguments args)
{
	if(!ctx) {
		return -1;
	}

	if( (args.need & ctx->have) != args.need ) {
		return -1;
	}

	if( args.need_state && !(args.need_state & ctx->state) ) {
		return -1;
	}

	return ctx_clear(ctx, args.clear);
}


static int ctx_provide(trsa_ctx ctx, int retval, struct ctx_provide_arguments args)
{
	if(!ctx) {
		return -1;
	}

	if(retval < 0) {
		ctx_clear(ctx, args.provide);
		if(args.state_error) {
			ctx->state = args.state_error;
		}
	} else {
		ctx->have |= args.provide;
		if(args.state_success) {
			ctx->state = args.state_success;
		}
	}

	if(args.state) {
		ctx->state = args.state;
	}

	return retval;
}

static int ctx_verify(trsa_ctx ctx, uint32_t parts)
{
	if(!ctx) {
		return -1;
	}

	if(parts & CTX_PUBLIC) {
		if(ctx->l < 1 || ctx->t < 1) return -1;
		if(ctx->t > ctx->l-1) return -1;
		/* ... */
	}

	if(parts & CTX_PRIVATE) {

	}

	if(parts & CTX_SHARES) {

	}

	if(parts & CTX_PARTIALS) {

	}

	if(parts & CTX_CHALLENGE) {

	}

	if(parts & CTX_MY_SHARE) {
		if(ctx->my_i < 1 || ctx->my_i > ctx->l) return -1;
	}

	return 0;
}
