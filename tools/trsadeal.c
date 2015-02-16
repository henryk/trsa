#define _GNU_SOURCE
#include "libtrsa.h"

#include "helpers.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>


#define USAGE do { fprintf(stderr, "Usage: %s k n bits name\nk -- Number of parts needed to compute\nn -- Number of parts total\nbits -- key size in bits\nname -- basename of output files\n", argv[0]); } while(0)
#define CHECK_( exp, label ) do { if(!(exp)) { fputs(label " failed. Aborting.\n", stderr); goto abort;} } while(0)
#define CHECK_ALLOC(exp) CHECK_( exp, #exp )
#define CHECK_RETVAL(exp) CHECK_( (exp) >= 0, #exp )

int main(int argc, char **argv) {
	int retval = -1;
	trsa_ctx dealer = NULL;
	int n, k, bits;
	char *name = NULL;
	uint8_t *b = NULL;
	size_t b_length = 0;
	mode_t old_umask;


	if(argc < 5) {
		USAGE;
		goto abort;
	}

	k = atoi(argv[1]);
	n = atoi(argv[2]);
	bits = atoi(argv[3]);
	name = argv[4];

	CHECK_EXP( dealer = trsa_init() );
	CHECK_RETVAL( trsa_key_generate(dealer, bits, k-1, n) );

	old_umask = umask(S_IWGRP | S_IWOTH);
	CHECK_RETVAL( trsa_pubkey_get(dealer, &b, &b_length) );
	CHECK_RETVAL( write_data(b, b_length, "%s.pub", name) );
	umask(old_umask);

	free(b);
	b=NULL;

	old_umask = umask(S_IRWXG | S_IRWXO);
	for(int i = 1; i<= n; i++) {
		CHECK_RETVAL( trsa_share_get(dealer, i, &b, &b_length) );
		CHECK_RETVAL( write_data(b, b_length, "%s-%i.share", name, i) );

		free(b);
		b = NULL;
	}
	umask(old_umask);

	retval = 0;


abort:
	trsa_fini(dealer);
	free(b);
	return retval;
}
