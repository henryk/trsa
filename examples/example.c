/*
 ============================================================================
 Name        : example.c
 Author      : Henryk Plötz <henryk@ploetzli.ch>
 Version     :
 Copyright   : (c) 2015 Henryk Plötz
 Description : Uses shared library to print greeting
 To run the resulting executable the LD_LIBRARY_PATH must be
 set to ${project_loc}/libtrsa/.libs
 Alternatively, libtool creates a wrapper shell script in the
 build directory of this program which can be used to run it.
 Here the script will be called example.
 ============================================================================
 */

#include "libtrsa.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gmp.h" // FIXME Test code

#define FAIL(x) do { fprintf(stderr, x "\n"); goto abort; } while(0)
#define NUMBITS 2048
#define SHARES_TOTAL 5
#define SHARES_NEEDED 3

static int copy_share(trsa_ctx source, trsa_ctx destination, int i) {
	uint8_t *data = NULL;
	size_t data_length = 0;

	int retval = trsa_share_get(source, i, &data, &data_length);
	if(retval < 0)
		FAIL("trsa_share_get() failed");

	retval = trsa_share_set(destination, data, data_length);
	if(retval < 0)
		FAIL("trsa_share_set() failed");

	retval = 0;
	abort: free(data);
	return retval;
}

static int copy_pubkey(trsa_ctx source, trsa_ctx destination) {
	uint8_t *data = NULL;
	size_t data_length = 0;

	int retval = trsa_pubkey_get(source, &data, &data_length);
	if(retval < 0)
		FAIL("trsa_pubkey_get() failed");

	retval = trsa_pubkey_set(destination, data, data_length);
	if(retval < 0)
		FAIL("trsa_pubkey_set() failed");

	retval = 0;
	abort: free(data);
	return retval;
}

static int contribute_partial(trsa_ctx source, trsa_ctx destination,
		const uint8_t *challenge, size_t challenge_length) {
	uint8_t *response = NULL;
	size_t response_length = 0;

	int retval = trsa_decrypt_partial(source, challenge, challenge_length,
			&response, &response_length);
	if(retval < 0)
		FAIL("trsa_decrypt_partial() failed");

	retval = trsa_decrypt_contribute(destination, response, response_length);
	if(retval < 0)
		FAIL("trsa_decrypt_contribute() failed");

	retval = 0;
	abort: free(response);
	return retval;
}

int main(void) {
	int retval = -1;
	trsa_ctx dealer, encryptor, decryptor, participant_1, participant_3,
			participant_4, participant_5;
	trsa_ctx *contexts[] = {&dealer, &encryptor, &decryptor, &participant_1,
			&participant_3, &participant_4, &participant_5, NULL};
	trsa_ctx **ctx_ptr = contexts;
	uint8_t session_key[20];
	uint8_t *encrypted_session_key = NULL;
	size_t encrypted_session_key_length = 0;
	uint8_t restored_session_key[sizeof(session_key)];
	uint8_t *challenge = NULL;
	size_t challenge_length = 0;

	mpz_t x, x_[4], y, y_; 	// FIXME test code
	mpz_inits(x, x_[0], x_[1], x_[2], x_[3], y, y_, NULL);


	while(*ctx_ptr) {
		**ctx_ptr = trsa_init();
		if(!**ctx_ptr)
			FAIL("trsa_init() failed");
		ctx_ptr++;
	}

	if(trsa_key_generate(dealer, NUMBITS, SHARES_NEEDED - 1, SHARES_TOTAL) < 0)
		FAIL("trsa_key_generate() failed");

	if(copy_share(dealer, participant_1, 1) < 0)
		FAIL("copy_share(...,1) failed");
	if(copy_share(dealer, participant_3, 3) < 0)
		FAIL("copy_share(...,3) failed");
	if(copy_share(dealer, participant_4, 4) < 0)
		FAIL("copy_share(...,4) failed");
	if(copy_share(dealer, participant_5, 5) < 0)
		FAIL("copy_share(...,5) failed");

	if(copy_pubkey(dealer, encryptor) < 0)
		FAIL("copy_pubkey() failed");
	if(copy_pubkey(dealer, decryptor) < 0)
		FAIL("copy_pubkey() failed");


	// FIXME test code
	mpz_set_ui(y, 31); // y: Clear text

	if(trsa_op_pub(encryptor, y, x) < 0)  // x: Encrypted
		FAIL("trsa_op_pub() failed");

	if(trsa_op_partial(participant_1, x, x_[0]) < 0)
		FAIL("trsa_op_partial(1, ...) failed");

	if(trsa_op_partial(participant_3, x, x_[1]) < 0)
		FAIL("trsa_op_partial(3, ...) failed");

	if(trsa_op_partial(participant_4, x, x_[2]) < 0)
		FAIL("trsa_op_partial(4, ...) failed");

	if(trsa_op_partial(participant_5, x, x_[3]) < 0)
		FAIL("trsa_op_partial(5, ...) failed");

	if(trsa_op_combine_set(decryptor, 1, x_[0]) < 0)
		FAIL("trsa_op_combine_set(1, ...) failed");

	if(trsa_op_combine_set(decryptor, 3, x_[1]) < 0)
		FAIL("trsa_op_combine_set(3, ...) failed");

	if(trsa_op_combine_set(decryptor, 4, x_[2]) < 0)
		FAIL("trsa_op_combine_set(4, ...) failed");

	if(trsa_op_combine_set(decryptor, 5, x_[3]) < 0)
		FAIL("trsa_op_combine_set(5, ...) failed");

	if(trsa_op_combine_do(decryptor, x, y_) < 0)  // y_: Decrypted
		FAIL("trsa_op_combine_do() failed");

	if(mpz_cmp(y, y_) != 0)
		FAIL("y != y'");

	printf("Success!\n");

	if(trsa_encrypt_generate(encryptor, session_key, sizeof(session_key),
			&encrypted_session_key, &encrypted_session_key_length) < 0)
		FAIL("trsa_encrypt_generate() failed");


	if(trsa_decrypt_prepare(decryptor, encrypted_session_key,
			encrypted_session_key_length, &challenge, &challenge_length) < 0)
		FAIL("trsa_decrypt_prepare() failed");

	if(contribute_partial(participant_1, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,1) failed");
	if(contribute_partial(participant_1, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,1) second time failed");
	if(contribute_partial(participant_3, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,3) failed");
	if(contribute_partial(participant_4, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,4) failed");
	if(contribute_partial(participant_4, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,4) second time failed");
	if(contribute_partial(participant_5, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,5) failed");

	const char *wrong_val = "5:ABCabc";
	if(trsa_decrypt_contribute(decryptor, (const uint8_t*)wrong_val, strlen(wrong_val)) < 0)
		FAIL("trsa_decrypt_contribute(wrong_val) failed");

	if(trsa_decrypt_finish(decryptor, restored_session_key, sizeof(restored_session_key)) < 0)
		FAIL("trsa_decrypt_finish() failed");

	if(memcmp(session_key, restored_session_key, sizeof(restored_session_key)) != 0)
		FAIL("Restored session key doesn't match");

	printf("Success\n");
	retval = 0;

	abort: ctx_ptr = contexts;
	while(*ctx_ptr) {
		trsa_fini(**ctx_ptr);
		ctx_ptr++;
	}
	free(encrypted_session_key);
	free(challenge);
	mpz_clears(x, x_[0], x_[1], x_[2], x_[3], y, y_, NULL); // FIXME Test code
	return retval;
}
