#define _GNU_SOURCE
#include "libtrsa.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#define USAGE do { fprintf(stderr, "Usage: %s k n bits name\nk -- Number of parts needed to compute\nn -- Number of parts total\nbits -- key size in bits\nname -- basename of output files\n", argv[0]); } while(0)
#define CHECK_( exp, label ) do { if(!(exp)) { fprintf(stderr, label " failed. Aborting.\n"); goto abort;} } while(0)
#define CHECK_ALLOC(exp) CHECK_( exp, #exp )
#define CHECK_RETVAL(exp) CHECK_( (exp) >= 0, #exp )

static int write_data(const uint8_t *data, size_t data_length, const char *format, ...)
{
	int retval = -1;
	char *name = NULL;
	FILE *fp = NULL;
	va_list a;

	va_start(a, format);
	int r = vasprintf(&name, format, a);
	va_end(a);

	if(r < 0) {
		name = NULL;
		goto abort;
	}

	fp = fopen(name, "wb");
	if(!fp) {
		fprintf(stderr, "Couldn't open %s. Aborting.\n", name);
		goto abort;
	}

	if( fwrite(data, 1, data_length, fp) != data_length ) {
		fprintf(stderr, "Couldn't write to %s. Aborting.\n", name);
		goto abort;
	}

	retval = 0;

abort:
	free(name);
	if(fp) {
		fclose(fp);
	}
	return retval;
}

int main(int argc, char **argv) {
	int retval = -1;
	trsa_ctx dealer = NULL;
	int n, k, bits;
	char *name = NULL;
	uint8_t *b = NULL;
	size_t b_length = 0;


	if(argc < 5) {
		USAGE;
		goto abort;
	}

	k = atoi(argv[1]);
	n = atoi(argv[2]);
	bits = atoi(argv[3]);
	name = argv[4];

	CHECK_ALLOC( dealer = trsa_init() );
	CHECK_RETVAL( trsa_key_generate(dealer, bits, k-1, n) );

	CHECK_RETVAL( trsa_pubkey_get(dealer, &b, &b_length) );
	CHECK_RETVAL( write_data(b, b_length, "%s.pub", name) );
	free(b);
	b=NULL;

	for(int i = 1; i<= n; i++) {
		CHECK_RETVAL( trsa_share_get(dealer, i, &b, &b_length) );
		CHECK_RETVAL( write_data(b, b_length, "%s-%i.share", name, i) );

		free(b);
		b = NULL;
	}


abort:
	trsa_fini(dealer);
	free(b);
	return retval;
}
