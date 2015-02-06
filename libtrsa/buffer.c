/*
 * buffer.c
 *
 *  Created on: 4 Feb 2015
 *      Author: henryk
 */


#include "buffer.h"

#include <string.h>

static int ensure_space(struct buffer *b, size_t length)
{
	if(!b) {
		return -1;
	}

	size_t have_space = b->l - b->p;
	if(length > have_space) {
		if(!b->may_modify) {
			return -1;
		}

		size_t old_length = b->l;
		size_t new_length = b->p + length;
		uint8_t *new_d = realloc(b->d, new_length);
		if(!new_d) {
			return -1;
		}
		b->l = new_length;
		b->d = new_d;

		memset(b->d + old_length, 0, new_length - old_length);
	}

	return 0;
}

int buffer_put_uint16(buffer_t b, uint16_t data)
{
	int r = ensure_space(b, 2);
	if(r < 0) {
		return r;
	}

	if(!b->may_modify) {
		return -1;
	}


	b->d[b->p++] = (data >> 8) & 0xFF;
	b->d[b->p++] = (data >> 0) & 0xFF;
	return 0;
}

int buffer_put_bytes(buffer_t b, const uint8_t *data, size_t data_length)
{
	int r = ensure_space(b, data_length);
	if(r < 0) {
		return r;
	}

	if(!b->may_modify) {
		return -1;
	}

	if(data_length) {
		memcpy(b->d + b->p, data, data_length);
		b->p += data_length;
	}
	return 0;
}

int buffer_get_uint16(buffer_t b, uint16_t *data)
{
	int r = ensure_space(b, 2);
	if(r < 0) {
		return r;
	}

	if(!data) {
		return -1;
	}

	*data = b->d[b->p++] << 8;
	*data |= b->d[b->p++];

	return 0;

}

extern int buffer_get_bytes(buffer_t b, uint8_t const **data, size_t data_length)
{
	int r = ensure_space(b, data_length);
	if(r < 0) {
		return r;
	}

	if(!data) {
		return -1;
	}

	*data = b->d + b->p;
	b->p += data_length;

	return 0;
}



buffer_t buffer_alloc(size_t size_estimate)
{
	struct buffer *b = calloc(1, sizeof(*b));
	if(!b) {
		return NULL;
	}

	if(size_estimate) {
		b->d = calloc(1, size_estimate);
		if(!b->d) {
			free(b);
			return NULL;
		}
	}

	b->may_modify = 1;

	return b;
}

buffer_t buffer_init(const uint8_t *data, size_t data_length)
{
	struct buffer *b = calloc(1, sizeof(*b));
	if(!b) {
		return NULL;
	}

	b->d = (uint8_t*)data;  // Discarding const, but no modification will be allowed on the buffer through may_modify=0
	b->l = data_length;

	return b;
}


void buffer_free(buffer_t b)
{
	if(!b) {
		return;
	}

	if(b->may_modify) {
		free(b->d);
	}

	b->d = NULL;
	b->l = 0;
	b->p = 0;
	free(b);
}


void buffer_give_up(buffer_t *b, uint8_t **data, size_t *data_length)
{
	if(!b || !*b) {
		return;
	}

	*data = (*b)->d;
	*data_length = (*b)->p;

	free(*b);
	*b = NULL;
}