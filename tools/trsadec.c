#define _GNU_SOURCE
#include "libtrsa.h"

#include "helpers.h"
#include "buffer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#define USAGE do { fprintf(stderr, "Usage: %s n keyfile\nn -- Length of ephemeral key to generate in bytes\nkeyfile -- Name of the input file to read the generated key from\n", argv[0]); } while(0)

#define TRSA_SERVER_PORT 4235

static int handle_conn(int conn, const uint8_t *challenge, size_t challenge_length, trsa_ctx ctx)
{
	int retval = -1;
	int written = 0;
	int r;
	uint8_t b[100];
	uint8_t *in = NULL;
	size_t in_length = 0;
	buffer_t buffer = NULL;

	CHECK_EXP(buffer = buffer_alloc(0));

	while(written < challenge_length) {
		r = write(conn, challenge + written, challenge_length - written);
		if(r <= 0) {
			goto abort;
		}

		written += r;
	}

	shutdown(conn, SHUT_WR);

	do {
		r = read(conn, b, sizeof(b));
		if(r > 0) {
			CHECK_RETVAL(buffer_put_bytes(buffer, b, r));
		}
	} while(r > 0);

	buffer_give_up(&buffer, &in, &in_length);

	retval = trsa_decrypt_contribute(ctx, in, in_length);

abort:
	close(conn);
	buffer_free(buffer);
	memset(b, 0, sizeof(b));
	memset(in, 0, in_length);
	free(in);
	return retval;
}


int main(int argc, char **argv) {
	int retval = -1;
	trsa_ctx decryptor = NULL;
	char *in_name = NULL;
	int n;
	int srvsock = -1;
	struct sockaddr_in addr;
	uint8_t *b = NULL, *s =NULL, *c = NULL;
	size_t b_length = 0, c_length = NULL;


	if(argc < 3) {
		USAGE;
		goto abort;
	}

	n = atoi(argv[1]);
	in_name = argv[2];

	CHECK_EXP( decryptor = trsa_init() );
	CHECK_RETVAL( read_data(&b, &b_length, "%s", in_name) );
	CHECK_RETVAL( trsa_decrypt_prepare(decryptor, b, b_length, &c, &c_length) );

	free(b);
	b=NULL;

	srvsock = socket(AF_INET, SOCK_STREAM, 0);
	CHECK_EXP(srvsock >= 0);
	int one = 1;
	CHECK_RETVAL(setsockopt(srvsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TRSA_SERVER_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	CHECK_RETVAL( bind(srvsock, &addr, sizeof(addr)) );
	CHECK_RETVAL( listen(srvsock, 3) );

	while(1) {
		int conn = accept(srvsock, NULL, NULL);
		CHECK_RETVAL(conn);

		if( handle_conn(conn, c, c_length, decryptor) > 0 ) {
			break;
		}

	}

	CHECK_EXP( s = malloc(n) );
	CHECK_RETVAL( trsa_decrypt_finish(decryptor, s, n) );

	CHECK_EXP( fwrite(s, 1, n, stdout) == n );

	retval = 0;

abort:
	trsa_fini(decryptor);
	free(b);
	free(s);
	if(srvsock >= 0) {
		close(srvsock);
	}
	return retval;
}
