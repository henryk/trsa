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

#define FAIL(x) do { fprintf(stderr, x "\n"); goto abort; } while(0)
#define NUMBITS 10
#define SHARES_TOTAL 5
#define SHARES_NEEDED 3

static int copy_share(trsa_ctx source, trsa_ctx destination, int i) {
	uint8_t *data = NULL;
	size_t data_length = 0;

	int retval = trsa_share_get(source, i, data, &data_length);
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

	int retval = trsa_pubkey_get(source, data, &data_length);
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
			response, &response_length);
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
			participant_4;
	trsa_ctx *contexts[] = {&dealer, &encryptor, &decryptor, &participant_1,
			&participant_3, &participant_4, NULL};
	trsa_ctx **ctx_ptr = contexts;
	uint8_t session_key[20];
	uint8_t *encrypted_session_key = NULL;
	size_t encrypted_session_key_length = 0;
	uint8_t *restored_session_key = NULL;
	size_t restored_session_key_length = 0;
	uint8_t *challenge = NULL;
	size_t challenge_length = 0;

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

	if(copy_pubkey(dealer, encryptor) < 0)
		FAIL("copy_pubkey() failed");

	if(trsa_encrypt_generate(encryptor, session_key, sizeof(session_key),
			encrypted_session_key, &encrypted_session_key_length) < 0)
		FAIL("trsa_encrypt_generate() failed");

	if(trsa_decrypt_prepare(decryptor, encrypted_session_key,
			encrypted_session_key_length, challenge, &challenge_length) < 0)
		FAIL("trsa_decrypt_prepare() failed");

	if(contribute_partial(participant_1, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,1) failed");
	if(contribute_partial(participant_3, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,3) failed");
	if(contribute_partial(participant_4, decryptor, challenge, challenge_length)
			< 0)
		FAIL("contribute_partial(...,4) failed");

	if(trsa_decrypt_finish(decryptor, restored_session_key,
			&restored_session_key_length) < 0)
		FAIL("trsa_decrypt_finish() failed");

	if(sizeof(session_key) != restored_session_key_length)
		FAIL("Length of restored session key doesn't match");
	if(memcmp(session_key, restored_session_key, restored_session_key_length)
			!= 0)
		FAIL("Restored session key doesn't match");

	printf("Success\n");
	retval = 0;

	abort: ctx_ptr = contexts;
	while(*ctx_ptr) {
		trsa_fini(**ctx_ptr);
		ctx_ptr++;
	}
	free(encrypted_session_key);
	free(restored_session_key);
	return retval;
}
