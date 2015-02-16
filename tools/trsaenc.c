#define _GNU_SOURCE
#include "libtrsa.h"

#include "helpers.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define USAGE do { fprintf(stderr, "Usage: %s n pubkey keyfile\nn -- Length of ephemeral key to generate in bytes\npubkey -- Name of the public key input file\nkeyfile -- Name of the output file to write the generated key to\n", argv[0]); } while(0)

int main(int argc, char **argv) {
	int retval = -1;
	trsa_ctx encryptor = NULL;
	char *in_name = NULL, *out_name;
	int n;
	uint8_t *b = NULL, *s =NULL;
	size_t b_length = 0;


	if(argc < 4) {
		USAGE;
		goto abort;
	}

	n = atoi(argv[1]);
	in_name = argv[2];
	out_name = argv[3];

	CHECK_EXP( encryptor = trsa_init() );
	CHECK_RETVAL( read_data(&b, &b_length, "%s", in_name) );
	CHECK_RETVAL( trsa_pubkey_set(encryptor, b, b_length) );

	free(b);
	b=NULL;

	CHECK_EXP( s = malloc(n) );

	CHECK_RETVAL( trsa_encrypt_generate(encryptor, s, n, &b, &b_length) );
	CHECK_RETVAL( write_data(b, b_length, "%s", out_name) );

	CHECK_EXP( fwrite(s, 1, n, stdout) == n );

	retval = 0;

abort:
	trsa_fini(encryptor);
	free(b);
	free(s);
	return retval;
}
