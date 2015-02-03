#include <stdlib.h>
#include <stdio.h> // FIXME Debugging

#include <gmp.h>

#include "libtrsa.h"

#define PRIME_GENERATION_RETRIES 100
#define DEFAULT_PUBLIC_EXPONENT 3

struct trsa_context {
	mpz_t p, q, n, e, d;
};

trsa_ctx trsa_init ()
{
	struct trsa_context *ctx = calloc(1, sizeof(*ctx));
	if(!ctx) {
		return NULL;
	}

	mpz_inits(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, NULL);


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

int trsa_key_generate(trsa_ctx ctx, unsigned int numbits, unsigned int t, unsigned int l)
{
	if(!ctx) {
		return -1;
	}

	int retval = -1;

	int qlength = numbits/2;
	int plength = numbits - qlength;
	gmp_randstate_t rnd;
	mpz_t phi_n, pminus, qminus, delta, tmp, tmp2;

	gmp_randinit_default(rnd);
	mpz_inits(phi_n, pminus, qminus, delta, tmp, tmp2, NULL);

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

	// FIXME Debugging start
	printf("q: "); mpz_out_str(stdout, 10, ctx->q); printf("\n");
	printf("p: "); mpz_out_str(stdout, 10, ctx->p); printf("\n");
	printf("n: "); mpz_out_str(stdout, 10, ctx->n); printf("\n");
	printf("phi_n: "); mpz_out_str(stdout, 10, phi_n); printf("\n");
	printf("e: "); mpz_out_str(stdout, 10, ctx->e); printf("\n");
	printf("d: "); mpz_out_str(stdout, 10, ctx->d); printf("\n");
	// FIXME Debugging end

	retval = 0;

abort:
	gmp_randclear(rnd);
	mpz_clears(phi_n, pminus, qminus, delta, tmp, tmp2, NULL);

	return retval;
}


int trsa_fini(trsa_ctx ctx)
{
	if(!ctx) {
		return -1;
	}


	mpz_clears(ctx->p, ctx->q, ctx->n, ctx->e, ctx->d, NULL);

	/* FIXME: Check if cleaning up actually destroys memory */
	free(ctx);
	return 0;
}


int trsa_share_get(trsa_ctx ctx, unsigned int i, uint8_t *data, size_t *data_length) { return -1; }
int trsa_share_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) { return -1; }

int trsa_encrypt_generate(trsa_ctx ctx,
		uint8_t *session_key, size_t session_key_length,
		uint8_t *encrypted_session_key, size_t *encrypted_session_key_length) { return -1; }

int trsa_decrypt_prepare(trsa_ctx ctx,
		const uint8_t *encrypted_session_key, size_t encrypted_session_key_length,
		uint8_t *challenge, size_t *challenge_length) { return -1; }

int trsa_decrypt_partial(trsa_ctx ctx,
		const uint8_t *challenge, size_t challenge_length,
		uint8_t *response, size_t *response_length) { return -1; }

int trsa_decrypt_contribute(trsa_ctx ctx,
		const uint8_t *response, size_t response_length) { return -1; }

int trsa_decrypt_finish(trsa_ctx ctx,
		uint8_t *session_key, size_t *session_key_length) { return -1; }

int trsa_pubkey_get(trsa_ctx ctx, uint8_t *data, size_t *data_length) { return -1; }
int trsa_pubkey_set(trsa_ctx ctx, const uint8_t *data, size_t data_length) { return -1; }
