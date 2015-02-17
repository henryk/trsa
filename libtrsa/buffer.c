/*
 * buffer.c
 *
 *  Created on: 4 Feb 2015
 *      Author: henryk
 */

#include <string.h>

#include <gmp.h>

#include "buffer.h"

#define ASCII_BASE 62

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

static size_t estimate_size_uint16(uint16_t x)
{
	size_t s = 1;
	for(int m=ASCII_BASE; m<UINT16_MAX; m*=ASCII_BASE) {
		if(x >= m) {
			s+=1;
		}
	}
	return s;
}

static size_t estimate_size(const struct buffer_description *data)
{
	size_t s = 0;
	if(!data) {
		return 0;
	}

	while(data->type != BUFFER_DESCRIPTION_TYPE_NULL) {
		switch(data->type) {
		case BUFFER_DESCRIPTION_TYPE_NULL: break;
		case BUFFER_DESCRIPTION_TYPE_BYTES:
			if(data->data.bytes.data_length) {
				s += *(data->data.bytes.data_length);
			}
			break;
		case BUFFER_DESCRIPTION_TYPE_FIXED_BYTES:
			s += data->data.fixed_bytes.data_length;
			break;
		case BUFFER_DESCRIPTION_TYPE_UINT16:
			s += 2;
			break;
		case BUFFER_DESCRIPTION_TYPE_UINT16_ASCII:
			if(data->data.uint16) {
				s+=estimate_size_uint16(*data->data.uint16);
			}
			break;
		case BUFFER_DESCRIPTION_TYPE_MPZ:
			s += 2;
			if(data->data.mpz) {
				s += (mpz_sizeinbase (*(data->data.mpz), 2) + 7) / 8;
			}
			break;
		case BUFFER_DESCRIPTION_TYPE_MPZ_ASCII:
			if(data->data.mpz) {
				s += mpz_sizeinbase (*(data->data.mpz), ASCII_BASE);
			}
			break;
		}

		data++;
	}

	return s;
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

static int to_ascii(unsigned int x)
{
	if(x < 10) {
		return '0' + x;
	}
	if(x < 36) {
		return 'A' + x - 10;
	}
	if(x < 62) {
		return 'a' + x - 10 - 26;
	}
	return -1;
}

static int from_ascii(unsigned char c)
{
	if(c >= '0' && c <= '9') {
		return c - '0';
	}
	if(c >= 'A' && c <= 'Z') {
		return c - 'A' + 10;
	}
	if(c >= 'a' && c <= 'z') {
		return c - 'a' + 10 + 26;
	}
	return -1;
}

int buffer_put_uint16_ascii(buffer_t b, uint16_t data)
{
	size_t size_estimate = estimate_size_uint16(data);
	int r = ensure_space(b, size_estimate);
	if(r < 0) {
		return r;
	}

	if(!b->may_modify) {
		return -1;
	}

	int pos = size_estimate;
	do {
		pos--;
		int encoded = to_ascii(data % ASCII_BASE);
		if(encoded < 0) {
			return -1;
		}
		b->d[b->p + pos] = encoded;
		data /= ASCII_BASE;
	} while(data > 0);

	b->p += size_estimate;

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

int buffer_put_mpz(buffer_t b, mpz_t data)
{
	int retval = -1;
	size_t d_length = 0;
	uint8_t *d = mpz_export(NULL, &d_length, 1, 1, 1, 0, data);

	int r = ensure_space(b, 2 + d_length + 1);
	if(r < 0) {
		retval = r;
		goto abort;
	}

	if(!b->may_modify) {
		goto abort;
	}

	if(!data || d_length > UINT16_MAX) {
		goto abort;
	}

	if( buffer_put_uint16(b, d_length) < 0) {
		goto abort;
	}

	if( buffer_put_bytes(b, d, d_length) < 0) {
		goto abort;
	}

	b->d[b->p++] = (mpz_sgn(data) < 0) ? 1 : 0;

	retval = 0;

abort:
	free(d);
	return retval;

}

int buffer_put_mpz_ascii(buffer_t b, mpz_t data)
{
	int retval = -1;
	size_t size_estimate = mpz_sizeinbase (data, ASCII_BASE);
	if(mpz_sgn(data) < 0) {
		size_estimate += 1;
	}
	mpz_t tmp;

	mpz_init(tmp);

	int r = ensure_space(b, size_estimate);
	if(r < 0) {
		retval = r;
		goto abort;
	}

	if(!b->may_modify) {
		goto abort;
	}

	mpz_set(tmp, data);

	if(mpz_sgn(tmp) < 0) {
		b->d[b->p] = '-';
		mpz_neg(tmp, tmp);
	}

	size_t pos = size_estimate;

	do {
		if(pos == 0) {
			goto abort;
		}
		pos--;

		int encoded = to_ascii( mpz_fdiv_ui(tmp, ASCII_BASE) );
		if(encoded < 0) {
			goto abort;
		}

		b->d[b->p + pos] = encoded;
		mpz_fdiv_q_ui(tmp, tmp, ASCII_BASE);
	} while(mpz_cmp_ui(tmp, 0) != 0);

	b->p += size_estimate;

	retval = 0;

abort:
	mpz_clear(tmp);
	return retval;
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

int buffer_get_uint16_ascii(buffer_t b, uint16_t *data)
{
	if(!data) {
		return -1;
	}

	size_t length = 0;
	uint32_t tmp = 0;

	while(ensure_space(b, length+1) >= 0) {
		int decoded = from_ascii(b->d[b->p + length]);
		if(decoded >= 0) {
			tmp *= ASCII_BASE;
			tmp += decoded;
			length++;
		} else {
			break;
		}
		if(tmp > UINT16_MAX) {
			return -1;
		}
	}

	*data = tmp;
	b->p += length;

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

int buffer_get_mpz(buffer_t b, mpz_t data)
{
	uint16_t d_length = 0;
	const uint8_t *d = NULL;

	if( buffer_get_uint16(b, &d_length) < 0) {
		return -1;
	}

	int r = ensure_space(b, d_length + 1);
	if(r < 0) {
		return r;
	}

	if( buffer_get_bytes(b, &d, d_length) < 0) {
		return -1;
	}

	mpz_import(data, d_length, 1, 1, 1, 0, d);

	if( b->d[b->p++] ) {
		mpz_neg(data, data);
	}

	return 0;
}

int buffer_get_mpz_ascii(buffer_t b, mpz_t data)
{
	if(!data) {
		return -1;
	}

	size_t length = 0;
	int is_neg = 0;
	mpz_t tmp;
	mpz_init(tmp);

	while(ensure_space(b, length+1) >= 0) {
		if(length == 0 && b->d[b->p + length] == '-') {
			is_neg = 1;
			length++;
		} else {
			int decoded = from_ascii(b->d[b->p + length]);
			if(decoded >= 0) {
				mpz_mul_ui(tmp, tmp, ASCII_BASE);
				mpz_add_ui(tmp, tmp, decoded);
				length++;
			} else {
				break;
			}
		}
	}

	if(is_neg) {
		mpz_neg(tmp, tmp);
	}

	mpz_set(data, tmp);
	b->p += length;

	mpz_clear(tmp);

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

buffer_t buffer_alloc_put_(const struct buffer_description *data)
{
	size_t size_estimate = estimate_size(data);
	struct buffer *b = buffer_alloc(size_estimate);
	if(!b) {
		return NULL;
	}

	if(buffer_put_(b, data) < 0) {
		buffer_free(b);
		b = NULL;
	}
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

int buffer_put_(buffer_t b, const struct buffer_description *data)
{
	if(!b || !data) {
		return -1;
	}

	int retval = 0;

	while(data->type != BUFFER_DESCRIPTION_TYPE_NULL) {
		switch(data->type) {
		case BUFFER_DESCRIPTION_TYPE_NULL: break;
		case BUFFER_DESCRIPTION_TYPE_BYTES:
			if(!data->data.bytes.data || !data->data.bytes.data_length) {
				retval = -1;
			} else {
				retval = buffer_put_bytes(b, *data->data.bytes.data, *data->data.bytes.data_length);
			}
			break;
		case BUFFER_DESCRIPTION_TYPE_FIXED_BYTES:
			retval = buffer_put_bytes(b, data->data.fixed_bytes.data, data->data.fixed_bytes.data_length);
			break;
		case BUFFER_DESCRIPTION_TYPE_UINT16: // Fall-through
		case BUFFER_DESCRIPTION_TYPE_UINT16_ASCII:
			if(!data->data.uint16) {
				retval = -1;
			} else {
				retval = ((data->type==BUFFER_DESCRIPTION_TYPE_UINT16) ? buffer_put_uint16 : buffer_put_uint16_ascii)
						(b, *data->data.uint16);
			}
			break;
		case BUFFER_DESCRIPTION_TYPE_MPZ: // Fall-through
		case BUFFER_DESCRIPTION_TYPE_MPZ_ASCII:
			if(!data->data.mpz) {
				retval = -1;
			} else {
				retval = ((data->type==BUFFER_DESCRIPTION_TYPE_MPZ) ? buffer_put_mpz : buffer_put_mpz_ascii)
						(b, *data->data.mpz);
			}
			break;
		}

		if(retval < 0) {
			break;
		}

		data++;
	}

	return retval;
}

int buffer_get_(buffer_t b, const struct buffer_description *data)
{
	if(!b || !data) {
		return -1;
	}

	int retval = 0;

	while(data->type != BUFFER_DESCRIPTION_TYPE_NULL) {
		switch(data->type) {
		case BUFFER_DESCRIPTION_TYPE_NULL: break;
		case BUFFER_DESCRIPTION_TYPE_BYTES:
			if(!data->data.bytes.data || !data->data.bytes.data_length) {
				retval = -1;
			} else {
				retval = buffer_get_bytes(b, data->data.bytes.data, *(data->data.bytes.data_length));
			}
			break;
		case BUFFER_DESCRIPTION_TYPE_FIXED_BYTES:
			{
				const uint8_t *tmp;
				retval = buffer_get_bytes(b, &tmp, data->data.fixed_bytes.data_length);
				if(retval >= 0) {
					if(memcmp(tmp, data->data.fixed_bytes.data, data->data.fixed_bytes.data_length) != 0) {
						retval = -1;
					}
				}
			}
			break;
		case BUFFER_DESCRIPTION_TYPE_UINT16:
			retval = buffer_get_uint16(b, data->data.uint16);
			break;
		case BUFFER_DESCRIPTION_TYPE_UINT16_ASCII:
			retval = buffer_get_uint16_ascii(b, data->data.uint16);
			break;
		case BUFFER_DESCRIPTION_TYPE_MPZ: // Fall-through
		case BUFFER_DESCRIPTION_TYPE_MPZ_ASCII:
			if(!data->data.mpz) {
				retval = -1;
			} else {
				retval = ((data->type==BUFFER_DESCRIPTION_TYPE_MPZ) ? buffer_get_mpz : buffer_get_mpz_ascii)
						(b, *data->data.mpz);
			}
			break;
		}

		if(retval < 0) {
			break;
		}

		data++;
	}

	return retval;
}
