#include <stdlib.h>

#include <gmp.h>

#include "libtrsa.h"

struct trsa_context {
	int foo;
};

trsa_ctx trsa_init ()
{
	struct trsa_context *ctx = calloc(1, sizeof(*ctx));
	if(!ctx) {
		return NULL;
	}

	return ctx;
}


int trsa_fini(trsa_ctx ctx)
{
	if(!ctx) {
		return -1;
	}

	/* FIXME: Clean up */
	free(ctx);
	return 0;
}
