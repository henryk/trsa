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
#include <netdb.h>

#define USAGE do { fprintf(stderr, "Usage: %s share server\nshare -- Name of the file to read the private key share from\nserver -- host or host:port to contact the trsadec program at\n", argv[0]); } while(0)

#define TRSA_SERVER_PORT_STR "4235"

int main(int argc, char **argv) {
	int retval = -1;
	trsa_ctx part = NULL;
	char *in_name = NULL, *server = NULL;
	int conn = -1, r;
	struct addrinfo *addr = NULL, *a, hints;
	uint8_t *b = NULL, c[100], *p = NULL;
	size_t b_length = 0, p_length = 0;
	buffer_t buffer = NULL;


	if(argc < 3) {
		USAGE;
		goto abort;
	}

	in_name = argv[1];
	CHECK_EXP( server = strdup(argv[2]) );

	CHECK_EXP( part = trsa_init() );
	CHECK_RETVAL( read_data(&b, &b_length, "%s", in_name) );
	CHECK_RETVAL( trsa_share_set(part, b, b_length) );

	free(b);
	b=NULL;

	char *pos = strrchr(server, ':');
	if(pos) {
		*pos = 0;
		pos++;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;

	CHECK_RETVAL( getaddrinfo( server, pos ? pos : TRSA_SERVER_PORT_STR, &hints, &addr) );

	for(a = addr; a; a = a->ai_next) {
		conn = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if(conn < 0) {
			continue;
		}

		if (connect(conn, a->ai_addr, a->ai_addrlen) >= 0) {
			break;
		}

		close(conn);
		conn = -1;
	}

	CHECK_EXP( buffer = buffer_alloc(0) );

	do {
		r = read(conn, c, sizeof(c));
		if(r > 0) {
			CHECK_RETVAL(buffer_put_bytes(buffer, c, r));
		}
	} while(r > 0);

	buffer_give_up(&buffer, &b, &b_length);

	CHECK_RETVAL( trsa_decrypt_partial(part, b, b_length, &p, &p_length) );

	int written = 0;
	while(written < p_length) {
		r = write(conn, p + written, p_length - written);
		if(r <= 0) {
			goto abort;
		}

		written += r;
	}


abort:
	if(conn >= 0) {
		close(conn);
	}
	if(addr) freeaddrinfo(addr);
	trsa_fini(part);
	free(b);
	free(p);
	free(server);
	return retval;
}
