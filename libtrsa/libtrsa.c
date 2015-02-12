#include <stdlib.h>
#include <string.h>
#include <stdio.h> // FIXME Debugging

#include <gmp.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "buffer.h"
#include "libtrsa.h"

#define PRIME_GENERATION_RETRIES 100
#define DEFAULT_PUBLIC_EXPONENT 65537
#define SECONDARY_SECURITY_PARAMETER 128

#define PBKDF2_ITERATIONS 1000
#define PBKDF2_DIGEST EVP_sha512()
#define MAXIMUM_SESSION_KEY_LENGTH 60000

#define MAGIC_SIZE 8
#define MAGIC_SHARE   "TRSAs\r\n\x00"
#define MAGIC_PUBKEY  "TRSAp\r\n\x00"
#define MAGIC_KEMKEY  "TRSAk\r\n\x00"

struct trsa_context {
	mpz_t p, q, n, e, d;
	mpz_t *s, *x_, my_s,  y_challenge;
	int t, l, my_i;

	uint32_t have;
	uint32_t state;
};

#define CTX_PUBLIC        (1L<<0)
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

struct ctx_require_arguments {
	uint32_t need, clear;
	uint32_t need_state;
};

struct ctx_provide_arguments {
	uint32_t provide;
	uint32_t state, state_good, state_error;
	uint32_t clear;
};

static int ctx_require(trsa_ctx ctx, struct ctx_require_arguments args);
static int ctx_provide(trsa_ctx ctx, int retval, struct ctx_provide_arguments args);

trsa_ctx trsa_init ()
{
	struct trsa_context *ctx = calloc(1, sizeof(*ctx));
	if(!ctx) {
		return NULL;
	}

	mpz_inits(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, ctx->my_s, ctx->y_challenge, NULL);


	return ctx;
}

int trsa_fini(trsa_ctx ctx)
{
	if(!ctx) {
		return -1;
	}


	mpz_clears(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, ctx->my_s, ctx->y_challenge, NULL);

	if(ctx->s != NULL) {
		for(int i=0; i<ctx->l; i++) {
			mpz_clear(ctx->s[i]);
		}
		free(ctx->s);
	}

	if(ctx->x_ != NULL) {
		for(int i=0; i<ctx->l; i++) {
			mpz_clear(ctx->x_[i]);
		}
		free(ctx->x_);
	}

	/* FIXME: Check if cleaning up actually destroys memory */
	free(ctx);
	return 0;
}

static unsigned int FIRST_PRIMES[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
		31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
		107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
		181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
		263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347,
		349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
		433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
		521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
		613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
		701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
		809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883,
		887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991,
		997};

static int accept_prime(mpz_t p, unsigned int t)
{
	int retval = 0;
	mpz_t minusonehalf;
	mpz_init(minusonehalf);

	if(mpz_probab_prime_p(p, 25) == 0) {
		goto abort;
	}

	mpz_sub_ui(minusonehalf, p, 1);
	mpz_divexact_ui(minusonehalf, minusonehalf, 2);

	for(int i=0; i<sizeof(FIRST_PRIMES)/sizeof(FIRST_PRIMES[0]); i++) {
		if(FIRST_PRIMES[i] >= 3*t*t) {
			break;
		}
		if( mpz_fdiv_ui(minusonehalf, FIRST_PRIMES[i]) == 0) {
			goto abort;
		}
	}

	// FIXME: handle primes greater than FIRST_PRIMES[-1]

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
	// FIXME Improve by retrieving more than one byte at a time
	uint8_t buffer;
	mpz_set_ui(out, 0);

	while(b > 8) {
		if(RAND_bytes(&buffer, sizeof(buffer)) != 1) {
			return -1;
		}
		mpz_mul_2exp(out, out, 8);
		mpz_add_ui(out, out, buffer);

		b -= 8;
	}

	if(b > 0) {
		if(RAND_bytes(&buffer, sizeof(buffer)) != 1) {
			return -1;
		}
		mpz_mul_2exp(out, out, b);

		buffer >>= (8-b);

		mpz_add_ui(out, out, buffer);

		b -= b;
	}

	buffer = 0;

	return 0;
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

	// FIXME Debugging start
	printf("m: "); mpz_out_str(stdout, 10, m); printf("\n");
	printf("u: %zi\n", u);
	printf("t: "); mpz_out_str(stdout, 10, t); printf("\n");
	// FIXME Debugging end

	do {
		if(random_bits(out, u) < 0) {
			goto abort;
		}
		// FIXME Debugging start
		printf("x: "); mpz_out_str(stdout, 10, out); printf("\n");
		// FIXME Debugging end
	} while(mpz_cmp(out, t) >= 0);

	mpz_mod(out, out, m);
	retval = 0;

	// FIXME Debugging start
	printf("r: "); mpz_out_str(stdout, 10, out); printf("\n");
	// FIXME Debugging end

abort:
	mpz_clear(t);
	return retval;
}

int trsa_key_generate(trsa_ctx ctx, unsigned int numbits, unsigned int t, unsigned int l)
{
	START(.clear=CTX_ALL);

	int qlength = numbits/2;
	int plength = numbits - qlength;
	mpz_t phi_n, pminus, qminus, delta, c_max, tmp, tmp2;
	mpz_t *c = NULL;

	ctx->t = t;
	ctx->l = l;
	ctx->s = NULL;

	mpz_inits(phi_n, pminus, qminus, delta, c_max, tmp, tmp2, NULL);

	if(random_bits(ctx->p, plength) < 0) {
		goto abort;
	}

	if(random_bits(ctx->q, qlength) < 0) {
		goto abort;
	}

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

	if(retries <= 0) {
		goto abort;
	}

	retries = PRIME_GENERATION_RETRIES;
	do {
		mpz_nextprime(ctx->q, ctx->q);

		if(accept_prime(ctx->q, t) && mpz_cmp(ctx->p, ctx->q) != 0) {
			break;
		}

	} while(--retries > 0);

	if(retries <= 0) {
		goto abort;
	}

	mpz_sub_ui(pminus, ctx->p, 1);
	mpz_sub_ui(qminus, ctx->q, 1);

	mpz_mul(ctx->n, ctx->p, ctx->q);
	mpz_mul(phi_n, pminus, qminus);

	mpz_set_ui(ctx->e, DEFAULT_PUBLIC_EXPONENT);

	retries = PRIME_GENERATION_RETRIES;
	do {
		// GCD(e, 4*DELTA^2)
		mpz_fac_ui(delta, l);
		mpz_mul(tmp2, delta, delta);
		mpz_mul_ui(tmp2, tmp2, 4);
		mpz_gcd(tmp, ctx->e, tmp2);

		// GCD(e, phi_n)
		mpz_gcd(tmp2, ctx->e, phi_n);

		if(mpz_cmp_ui(tmp, 1) == 0 && mpz_cmp_ui(tmp2, 1) == 0) {
			break;
		}

		mpz_nextprime(ctx->e, ctx->e);
	} while(--retries > 0);

	if(retries <= 0) {
		goto abort;
	}

	mpz_invert(ctx->d, ctx->e, phi_n);

	mpz_set(c_max, delta);
	mpz_mul(c_max, c_max, ctx->n);
	mpz_mul_2exp(c_max, c_max, t);
	mpz_mul_2exp(c_max, c_max, SECONDARY_SECURITY_PARAMETER);


	c = calloc(t+1, sizeof(*c));
	if(c == NULL) {
		goto abort;
	}

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
	if(ctx->s == NULL) {
		goto abort;
	}

	for(int i=0; i<l; i++) {
		mpz_init(ctx->s[i]);
	}

	for(int i=1; i<=l; i++) {
		evaluate_poly(ctx->s[i-1], c, t, i);
	}

	// FIXME Generate verification values

	// FIXME Debugging start
	printf("q: "); mpz_out_str(stdout, 10, ctx->q); printf("\n");
	printf("p: "); mpz_out_str(stdout, 10, ctx->p); printf("\n");
	printf("n: "); mpz_out_str(stdout, 10, ctx->n); printf("\n");
	printf("phi_n: "); mpz_out_str(stdout, 10, phi_n); printf("\n");
	printf("e: "); mpz_out_str(stdout, 10, ctx->e); printf("\n");
	printf("d: "); mpz_out_str(stdout, 10, ctx->d); printf("\n");
	for(int i=0; i<=t; i++) {
		printf("c_%i: ", i); mpz_out_str(stdout, 10, c[i]); printf("\n");
	}
	for(int i=1; i<=l; i++) {
		printf("s_%i: ", i); mpz_out_str(stdout, 10, ctx->s[i-1]); printf("\n");
	}
	// FIXME Debugging end

	retval = 0;

abort:
	mpz_clears(phi_n, pminus, qminus, delta, c_max, tmp, tmp2, NULL);
	if(c != NULL) {
		for(int i=0; i<=t; i++) {
			mpz_clear(c[i]);
		}
	}
	free(c);

	if(ctx->s != NULL && retval < 0) {
		for(int i=0; i<l; i++) {
			mpz_clear(ctx->s[i]);
		}
		free(ctx->s);
	}

	FINISH(CTX_PUBLIC | CTX_PRIVATE | CTX_SHARES);
}


static int dump_magic(buffer_t b, const char *magic)
{
	return buffer_put_bytes(b, (const uint8_t*)magic, MAGIC_SIZE);
}

static int verify_magic(buffer_t b, const char *magic)
{
	const uint8_t *data;

	int r = buffer_get_bytes(b, &data, MAGIC_SIZE);
	if(r < 0) return r;

	if(memcmp(data, magic, MAGIC_SIZE) != 0) {
		return -1;
	}

	return 0;
}


static size_t estimate_size_mpz(mpz_t op)
{
	return 2 + (mpz_sizeinbase (op, 2) + 7) / 8;
}

static int dump_mpz(buffer_t b, mpz_t op)
{
	int retval = -1;
	size_t data_length = 0;
	uint8_t *data = mpz_export(NULL, &data_length, 1, 1, 1, 0, op);

	// Note: sign is not stored. Are all values positive?

	if(data_length > 65535) {
		goto abort;
	}

	int r = buffer_put_uint16(b, data_length);
	ABORT_IF_ERROR(r);

	r = buffer_put_bytes(b, data, data_length);
	ABORT_IF_ERROR(r);

	retval = 0;

abort:
	free(data);
	return retval;
}

static int read_mpz(buffer_t b, mpz_t rop)
{
	int retval = -1;
	uint16_t data_length = 0;
	const uint8_t *data = NULL;;

	int r = buffer_get_uint16(b, &data_length);
	ABORT_IF_ERROR(r);

	r = buffer_get_bytes(b, &data, data_length);
	ABORT_IF_ERROR(r);

	mpz_import(rop, data_length, 1, 1, 1, 0, data);

	// Note: sign is not restored. Are all values positive?

	retval = 0;

abort:
	return retval;
}


static size_t estimate_size_public(trsa_ctx ctx)
{
	return 2 + estimate_size_mpz(ctx->n) + estimate_size_mpz(ctx->e);
}

static int dump_public(buffer_t b, trsa_ctx ctx)
{
	if(ctx->l > 65535) return -1;
	int r = buffer_put_uint16(b, ctx->l);
	if(r < 0) return r;
	r = dump_mpz(b, ctx->n);
	if(r < 0) return r;
	r = dump_mpz(b, ctx->e);
	if(r < 0) return r;
	return 0;
}

static int read_public(buffer_t b, trsa_ctx ctx)
{
	uint16_t tmp;
	int r = buffer_get_uint16(b, &tmp);
	if(r < 0) return r;
	ctx->l = tmp;
	r = read_mpz(b, ctx->n);
	if(r < 0) return r;
	r = read_mpz(b, ctx->e);
	if(r < 0) return r;
	return 0;
}

int trsa_share_get(trsa_ctx ctx, unsigned int i, uint8_t **data, size_t *data_length) {
	START(.need = CTX_PUBLIC | CTX_SHARES);

	if(!data || !data_length) {
		return -1;
	}

	if(*data || *data_length) {
		return -1; // Not implemented yet
	}

	// FIXME: Allow to iterate by using i=0
	if(i < 1 || i > ctx->l) {
		return -1;
	}

	// Write out public parameters, followed by private share parameters i, ctx->s[i-1]
	size_t size_estimate = MAGIC_SIZE;
	size_estimate += estimate_size_public(ctx);
	size_estimate += estimate_size_mpz(ctx->s[i-1]);

	buffer_t buffer = buffer_alloc(size_estimate);
	if(!buffer) {
		goto abort;
	}

	int r = dump_magic(buffer, MAGIC_SHARE);
	ABORT_IF_ERROR(r);

	r = dump_public(buffer, ctx);
	ABORT_IF_ERROR(r);

	r = buffer_put_uint16(buffer, i);  // FIXME: range of i
	ABORT_IF_ERROR(r);

	r = dump_mpz(buffer, ctx->s[i-1]);
	ABORT_IF_ERROR(r);

	buffer_give_up(&buffer, data, data_length);
	retval = 0;

abort:
	buffer_free(buffer);

	FINISH(0);
}

int trsa_share_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) {
	START(.clear = CTX_ALL | CTX_MY_SHARE);

	if(!data || !data_length) {
		return -1;
	}

	// Read in public parameters, followed by private share parameters my_i, ctx->my_s

	buffer_t buffer = buffer_init(data, data_length);
	if(!buffer) {
		goto abort;
	}

	int r = verify_magic(buffer, MAGIC_SHARE);
	ABORT_IF_ERROR(r);

	r = read_public(buffer, ctx);
	ABORT_IF_ERROR(r);

	uint16_t i;
	r = buffer_get_uint16(buffer, &i);
	ABORT_IF_ERROR(r);
	ctx->my_i = i;

	r = read_mpz(buffer, ctx->my_s);
	ABORT_IF_ERROR(r);

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
		buffer_t buffer, buffer_t x_buffer, mpz_t x,
		uint8_t *session_key, size_t session_key_length)
{
	int r = dump_mpz(x_buffer, x);
	if(r < 0) return r;

	r = dump_magic(buffer, MAGIC_KEMKEY);
	if(r < 0) return r;

	r = dump_public(buffer, ctx);
	if(r < 0) return r;

	if(session_key_length > MAXIMUM_SESSION_KEY_LENGTH) {
		// The OpenSSL API uses int as a length type, ward against overflows
		return -1;
	}
	r = buffer_put_uint16(buffer, session_key_length);
	if(r < 0) return r;

	r = PKCS5_PBKDF2_HMAC((char*)(x_buffer->d), x_buffer->p,
			buffer->d, buffer->p,
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

	mpz_t x, y;
	buffer_t x_buffer = NULL, buffer = NULL;

	mpz_inits(x, y, NULL);

	x_buffer = buffer_alloc(estimate_size_public(ctx));
	buffer = buffer_alloc(MAGIC_SIZE + estimate_size_public(ctx) + estimate_size_mpz(ctx->n) + 2);

	if(!x_buffer || !buffer) {
		goto abort;
	}

	// 1. Generate random x
	int r = random_number(x, ctx->n);
	ABORT_IF_ERROR(r);

	// 2. Encrypt (public operation) x to yield y
	r = trsa_op_pub(ctx, x, y);
	ABORT_IF_ERROR(r);

	// 3. Dump magic || pubkey || session_key_length into buffer,  dump x into x_buffer
	// 4. use buffer as salt and x_buffer as input to KDF, generate session_key output
	r = session_key_common(ctx, buffer, x_buffer, x, session_key, session_key_length);
	ABORT_IF_ERROR(r);

	// 5. Append y to buffer (is now magic || pubkey || y) and output encrypted_session_key
	r = dump_mpz(buffer, y);
	ABORT_IF_ERROR(r);

	buffer_give_up(&buffer, encrypted_session_key, encrypted_session_key_length);
	retval = 0;

abort:
	mpz_clears(x, y, NULL);
	buffer_free(x_buffer);
	buffer_free(buffer);

	FINISH(0);
}

int trsa_decrypt_prepare(trsa_ctx ctx,
		const uint8_t *encrypted_session_key, size_t encrypted_session_key_length,
		uint8_t **challenge, size_t *challenge_length) {

	START(.clear = CTX_ALL | CTX_CHALLENGE);

	if(!encrypted_session_key || !challenge || !challenge_length) {
		return -1;
	}

	mpz_t y;
	buffer_t buffer = NULL, output = NULL;

	mpz_init(y);

	buffer = buffer_init(encrypted_session_key, encrypted_session_key_length);
	if(!buffer) {
		goto abort;
	}

	// 1. Verify and read encrypted_session_key, yielding pubkey, y and session_key_length

	int r = verify_magic(buffer, MAGIC_KEMKEY);
	ABORT_IF_ERROR(r);

	r = read_public(buffer, ctx);
	ABORT_IF_ERROR(r);

	uint16_t tmp;
	r = buffer_get_uint16(buffer, &tmp);
	ABORT_IF_ERROR(r);

	r = read_mpz(buffer, y);
	ABORT_IF_ERROR(r);

	// 2. FIXME apply masking

	// 3. Record parameters in context

	mpz_set(ctx->y_challenge, y);

	// 4. Generate and output challenge   FIXME ASCII clear format
	output = buffer_alloc(estimate_size_mpz(ctx->n));

	r = dump_mpz(output, ctx->y_challenge);
	ABORT_IF_ERROR(r);

	buffer_give_up(&output, challenge, challenge_length);
	retval = 0;


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
	if(!in) {
		goto abort;
	}

	// 1. Read challenge   FIXME ASCII clear format
	int r = read_mpz(in, y_challenge);
	ABORT_IF_ERROR(r);

	// 2. Perform partial computation
	r = trsa_op_partial(ctx, y_challenge, x_partial);
	ABORT_IF_ERROR(r);

	// 3. Output response  i || x_partial  FIXME ASCII clear format
	out = buffer_alloc(2 + estimate_size_mpz(x_partial));
	if(!out) {
		goto abort;
	}

	r = buffer_put_uint16(out, ctx->my_i);  // FIXME verify range of i
	ABORT_IF_ERROR(r);

	r = dump_mpz(out, x_partial);
	ABORT_IF_ERROR(r);

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
	if(!buffer) {
		goto abort;
	}

	// 1. Read response i || x_partial   FIXME ASCII clear format
	int r = buffer_get_uint16(buffer, &i);
	ABORT_IF_ERROR(r);

	r = read_mpz(buffer, x_partial);
	ABORT_IF_ERROR(r);

	// 2. Set in context
	r = trsa_op_combine_set(ctx, i, x_partial);
	ABORT_IF_ERROR(r);

	retval = 0;

abort:
	mpz_clear(x_partial);
	buffer_free(buffer);

	FINISH(.state_good=STATE_DEC_READY);
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

	x_buffer = buffer_alloc(estimate_size_public(ctx));
	buffer = buffer_alloc(MAGIC_SIZE + estimate_size_public(ctx));
	if(!x_buffer || !buffer) {
		goto abort;
	}

	// 1. Execute combine operation, yielding x,  dump x into x_buffer
	int r = trsa_op_combine_do(ctx, ctx->y_challenge, x);
	ABORT_IF_ERROR(r);

	// 2. FIXME remove masking

	// 3. dump magic || pubkey || session_key_length into buffer,  x into x_buffer
	// 4. use buffer as salt and x_buffer as input to KDF, generate session_key output
	r = session_key_common(ctx, buffer, x_buffer, x, session_key, session_key_length);
	ABORT_IF_ERROR(r);

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
	size_t size_estimate = MAGIC_SIZE;
	size_estimate += estimate_size_public(ctx);

	buffer_t buffer = buffer_alloc(size_estimate);
	if(!buffer) {
		goto abort;
	}

	int r = dump_magic(buffer, MAGIC_PUBKEY);
	ABORT_IF_ERROR(r);

	r = dump_public(buffer, ctx);
	ABORT_IF_ERROR(r);

	buffer_give_up(&buffer, data, data_length);
	retval = 0;

abort:
	buffer_free(buffer);

	FINISH(0);
}

int trsa_pubkey_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) {
	START(.clear = CTX_ALL);

	if(!data || !data_length) {
		return -1;
	}

	// Read in public parameters

	buffer_t buffer = buffer_init(data, data_length);
	if(!buffer) {
		goto abort;
	}

	int r = verify_magic(buffer, MAGIC_PUBKEY);
	ABORT_IF_ERROR(r);

	r = read_public(buffer, ctx);
	ABORT_IF_ERROR(r);

	retval = 0;

abort:
	buffer_free(buffer);

	FINISH(CTX_PUBLIC);
}


int trsa_op_pub(trsa_ctx ctx, mpz_t in, mpz_t out)
{
	METHOD_START(ctx, .need = CTX_PUBLIC);

	mpz_powm_sec(out, in, ctx->e, ctx->n);
	// FIXME Debugging start
	printf("pub in: "); mpz_out_str(stdout, 10, in); printf("\n");
	printf("pub out: "); mpz_out_str(stdout, 10, out); printf("\n");
	// FIXME Debugging end

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

	return METHOD_FINISH(ctx, 0, 0);
}

int trsa_op_combine_set(trsa_ctx ctx, unsigned int i, mpz_t in)
{
	START(0);

	if(!ctx->x_) {
		ctx->x_ = calloc(ctx->l, sizeof(*ctx->x_));
		if(!ctx->x_) {
			goto abort;
		}
	}

	if(i < 1 || i > ctx->l) {
		goto abort;
	}

	mpz_set(ctx->x_[i-1], in);
	retval = 0;

abort:
	FINISH(CTX_PARTIALS);
}

static void lambda_S0j(mpz_t out, mpz_t *x_, int l, int j)
{
	mpz_fac_ui(out, l);
	for(int i=1; i<=l; i++) {
		if(mpz_cmp_ui(x_[i-1], 0) == 0) {
			continue;
		}
		if(i == j) continue;
		printf("do %i\n", i);
		mpz_mul_ui(out, out, i);
	}
	for(int i=1; i<=l; i++) {
		if(mpz_cmp_ui(x_[i-1], 0) == 0) {
			continue;
		}
		if(i == j) continue;
		if(i<j) {
			mpz_divexact_ui(out, out, j-i);
			mpz_neg(out, out);
		} else {
			mpz_divexact_ui(out, out, i-j);
		}
	}
	printf("lambda(%i): ", j); mpz_out_str(stdout, 10, out); printf("\n");
}

int trsa_op_combine_do(trsa_ctx ctx, mpz_t in, mpz_t out)
{
	START(.need = CTX_PUBLIC | CTX_PARTIALS);

	mpz_t a, b, w, tmp;
	mpz_inits(a, b, w, tmp, NULL);

	mpz_set_ui(w, 1);

	for(int j=1; j<=ctx->l; j++) {
		if(mpz_cmp_ui(ctx->x_[j-1], 0) == 0) {
			continue;
		}

		lambda_S0j(tmp, ctx->x_, ctx->l, j);
		mpz_mul_ui(tmp, tmp, 2);

		// TODO Insecure?
		// FIXME Debugging start
		printf("base: "); mpz_out_str(stdout, 10, ctx->x_[j-1]); printf("\n");
		printf("exp: "); mpz_out_str(stdout, 10, tmp); printf("\n");
		printf("mod: "); mpz_out_str(stdout, 10, ctx->n); printf("\n");
		// FIXME Debugging end
		mpz_powm(tmp, ctx->x_[j-1], tmp, ctx->n);
		mpz_mul(w, w, tmp);
		mpz_mod(w, w, ctx->n);
	}

	mpz_fac_ui(tmp, ctx->l);
	mpz_pow_ui(tmp, tmp, 2);
	mpz_mul_ui(tmp, tmp, 4);

	// TODO Insecure?
	mpz_gcdext(tmp, a, b, tmp, ctx->e);
	if(mpz_cmp_ui(tmp, 1) != 0) {
		goto abort;
	}

	// TODO Insecure?
	mpz_powm(out, w, a, ctx->n);
	mpz_powm(tmp, in, b, ctx->n);
	mpz_mul(out, out, tmp);
	mpz_mod(out, out, ctx->n);

	// FIXME Debugging start
	printf("a: "); mpz_out_str(stdout, 10, a); printf("\n");
	printf("b: "); mpz_out_str(stdout, 10, b); printf("\n");
	printf("w: "); mpz_out_str(stdout, 10, w); printf("\n");
	printf("out: "); mpz_out_str(stdout, 10, out); printf("\n");
	// FIXME Debugging end

	retval = 0;

abort:
	mpz_clears(a, b, w, tmp, NULL);

	FINISH(0, .clear = CTX_PARTIALS);
}


static int ctx_require(trsa_ctx ctx, struct ctx_require_arguments args)
{
	if(!ctx) {
		return -1;
	}
	// FIXME Implement remainder
	return 0;
}


static int ctx_provide(trsa_ctx ctx, int retval, struct ctx_provide_arguments args)
{
	if(!ctx) {
		return -1;
	}
	// FIXME Implement remainder
	return 0;
}
