#include <stdlib.h>
#include <string.h>
#include <stdio.h> // FIXME Debugging

#include <gmp.h>

#include <openssl/evp.h>

#include "buffer.h"
#include "libtrsa.h"

#define PRIME_GENERATION_RETRIES 100
#define DEFAULT_PUBLIC_EXPONENT 3
#define SECONDARY_SECURITY_PARAMETER 3 /* FIXME Increase to 128 */

#define PBKDF2_ITERATIONS 1000
#define PBKDF2_DIGEST EVP_sha512()
#define MAXIMUM_SESSION_KEY_LENGTH 60000

#define MAGIC_SIZE 8
#define MAGIC_SHARE   "TRSAs\r\n\x00"
#define MAGIC_PUBKEY  "TRSAp\r\n\x00"
#define MAGIC_KEMKEY  "TRSAk\r\n\x00"

struct trsa_context {
	mpz_t p, q, n, e, d;
	mpz_t *s, *x_, my_s;
	int t, l, my_i;
};

trsa_ctx trsa_init ()
{
	struct trsa_context *ctx = calloc(1, sizeof(*ctx));
	if(!ctx) {
		return NULL;
	}

	mpz_inits(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, ctx->my_s, NULL);


	return ctx;
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

int trsa_key_generate(trsa_ctx ctx, unsigned int numbits, unsigned int t, unsigned int l)
{
	if(!ctx) {
		return -1;
	}

	int retval = -1;

	int qlength = numbits/2;
	int plength = numbits - qlength;
	gmp_randstate_t rnd;
	mpz_t phi_n, pminus, qminus, delta, c_max, tmp, tmp2;
	mpz_t *c = NULL;

	ctx->t = t;
	ctx->l = l;
	ctx->s = NULL;
	// FIXME: Guard against memory leak in case of repeated calls

	gmp_randinit_default(rnd); // FIXME: Randomness
	mpz_inits(phi_n, pminus, qminus, delta, c_max, tmp, tmp2, NULL);

	mpz_urandomb(ctx->p, rnd, plength);
	mpz_urandomb(ctx->q, rnd, qlength);

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
		mpz_urandomm(c[i], rnd, c_max);
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
	gmp_randclear(rnd);
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

	return retval;
}


int trsa_fini(trsa_ctx ctx)
{
	if(!ctx) {
		return -1;
	}


	mpz_clears(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, ctx->my_s, NULL);

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

#define ABORT_IF_ERROR(r) do { if(r<0){retval=r; goto abort;} } while(0)

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
	if(!ctx || !data || !data_length) {
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
	int retval = -1;
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

	return retval;
}

int trsa_share_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) {
	if(!ctx || !data || !data_length) {
		return -1;
	}

	// Read in public parameters, followed by private share parameters my_i, ctx->my_s
	int retval = -1;

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

	return retval;
}

int trsa_encrypt_generate(trsa_ctx ctx,
		uint8_t *session_key, size_t session_key_length,
		uint8_t **encrypted_session_key, size_t *encrypted_session_key_length) {

	int retval = -1;
	mpz_t x, y;
	buffer_t x_buffer = NULL, buffer = NULL;
	gmp_randstate_t rnd;

	mpz_inits(x, y, NULL);
	gmp_randinit_default(rnd);

	x_buffer = buffer_alloc(estimate_size_public(ctx));
	buffer = buffer_alloc(MAGIC_SIZE + estimate_size_public(ctx) + estimate_size_mpz(ctx->n));

	if(!x_buffer || !buffer) {
		goto abort;
	}

	if(session_key_length > MAXIMUM_SESSION_KEY_LENGTH) {
		// The OpenSSL API uses int as a length type, ward against overflows
		goto abort;
	}

	// 1. Generate random x, dump into x_buffer  FIXME: randomness
	mpz_urandomm(x, rnd, ctx->n);
	int r = dump_mpz(x_buffer, x);
	ABORT_IF_ERROR(r);

	// 2. Dump magic, pubkey into buffer
	r = dump_magic(buffer, MAGIC_KEMKEY);
	ABORT_IF_ERROR(r);

	r = dump_public(buffer, ctx);
	ABORT_IF_ERROR(r);

	// 3. Encrypt (public operation) x to yield y
	r = trsa_op_pub(ctx, x, y);
	ABORT_IF_ERROR(r);

	// 4. use buffer as salt and x_buffer as input to KDF, generate session_key output
	r = PKCS5_PBKDF2_HMAC((char*)(x_buffer->d), x_buffer->p,
			buffer->d, buffer->p,
			PBKDF2_ITERATIONS, PBKDF2_DIGEST,
			session_key_length, session_key);
	if(!r) {
		goto abort;
	}

	// 5. Append y to buffer (is now magic || pubkey || y) and output encrypted_session_key
	r = dump_mpz(buffer, y);
	ABORT_IF_ERROR(r);

	buffer_give_up(&buffer, encrypted_session_key, encrypted_session_key_length);
	retval = 0;

abort:
	mpz_clears(x, y, NULL);
	buffer_free(x_buffer);
	buffer_free(buffer);
	gmp_randclear(rnd);

	return retval;
}

int trsa_decrypt_prepare(trsa_ctx ctx,
		const uint8_t *encrypted_session_key, size_t encrypted_session_key_length,
		uint8_t **challenge, size_t *challenge_length) { return -1; }

int trsa_decrypt_partial(trsa_ctx ctx,
		const uint8_t *challenge, size_t challenge_length,
		uint8_t **response, size_t *response_length) { return -1; }

int trsa_decrypt_contribute(trsa_ctx ctx,
		const uint8_t *response, size_t response_length) { return -1; }

int trsa_decrypt_finish(trsa_ctx ctx,
		uint8_t *session_key, size_t session_key_length) { return -1; }

int trsa_pubkey_get(trsa_ctx ctx, uint8_t **data, size_t *data_length) {
	if(!ctx || !data || !data_length) {
		return -1;
	}

	if(*data || *data_length) {
		return -1; // Not implemented yet
	}

	// Write out public parameters
	int retval = -1;
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

	return retval;
}

int trsa_pubkey_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) {
	if(!ctx || !data || !data_length) {
		return -1;
	}

	// Read in public parameters
	int retval = -1;

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

	return retval;
}


int trsa_op_pub(trsa_ctx ctx, mpz_t in, mpz_t out)
{
	if(!ctx) {
		return -1;
	}

	mpz_powm_sec(out, in, ctx->e, ctx->n);

	return 0;
}

int trsa_op_partial(trsa_ctx ctx, mpz_t in, mpz_t out)
{
	mpz_t exponent;
	mpz_init(exponent);
	int retval = -1;

	// exponent = (2 delta)
	mpz_fac_ui(exponent, ctx->l);
	mpz_mul_ui(exponent, exponent, 2);

	mpz_powm_sec(out, in, exponent, ctx->n);
	mpz_powm_sec(out, out, ctx->my_s, ctx->n);

	retval = 0;

	mpz_clear(exponent);
	return retval;
}

int trsa_op_combine_set(trsa_ctx ctx, unsigned int i, mpz_t in)
{
	int retval = -1;
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
	return retval;
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
	int retval = -1;
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
	return retval;
}
