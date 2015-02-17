/*
 * buffer.h
 *
 *  Created on: 4 Feb 2015
 *      Author: henryk
 */

#ifndef BUFFER_H_
#define BUFFER_H_

#include <stdlib.h>
#include <stdint.h>

#include <gmp.h>

struct buffer {
	uint8_t *d;
	size_t l;
	size_t p;
	unsigned int may_modify:1;
};

struct buffer_description {
	enum {
		BUFFER_DESCRIPTION_TYPE_NULL = 0,
		BUFFER_DESCRIPTION_TYPE_BYTES,
		BUFFER_DESCRIPTION_TYPE_UINT16,
		BUFFER_DESCRIPTION_TYPE_UINT16_ASCII,
		BUFFER_DESCRIPTION_TYPE_MPZ,
		BUFFER_DESCRIPTION_TYPE_MPZ_ASCII,
		BUFFER_DESCRIPTION_TYPE_FIXED_BYTES,
	} type;
	union {
		struct {
			const uint8_t **data; size_t *data_length;
		} bytes;
		uint16_t *uint16;
		mpz_t *mpz;
		struct {
			const uint8_t *data; size_t data_length;
		} fixed_bytes;
	} data;
};

#define BUFFER_FORMAT_BYTES(d, l) \
	{ .type = BUFFER_DESCRIPTION_TYPE_BYTES, .data = { .bytes = { d, l } } }
#define BUFFER_FORMAT_UINT16(d) \
	{ .type = BUFFER_DESCRIPTION_TYPE_UINT16, .data = { .uint16 = &(d) } }
#define BUFFER_FORMAT_UINT16_ASCII(d) \
	{ .type = BUFFER_DESCRIPTION_TYPE_UINT16_ASCII, .data = { .uint16 = &(d) } }
#define BUFFER_FORMAT_MPZ(d) BUFFER_FORMAT_MPZP(&(d))
#define BUFFER_FORMAT_MPZP(d) \
	{ .type = BUFFER_DESCRIPTION_TYPE_MPZ, .data = { .mpz = (d) } }
#define BUFFER_FORMAT_MPZ_ASCII(d) BUFFER_FORMAT_MPZP_ASCII(&(d))
#define BUFFER_FORMAT_MPZP_ASCII(d) \
	{ .type = BUFFER_DESCRIPTION_TYPE_MPZ_ASCII, .data = { .mpz = (d) } }
#define BUFFER_FORMAT_FIXED_BYTES(d, l) \
	{ .type = BUFFER_DESCRIPTION_TYPE_FIXED_BYTES, .data = { .fixed_bytes = { d, l } } }
#define BUFFER_FORMAT_END \
	{ .type = BUFFER_DESCRIPTION_TYPE_NULL }

#define BUFFER_FORMAT(...) \
	((const struct buffer_description[]) {__VA_ARGS__, BUFFER_FORMAT_END})

#define buffer_alloc_put(...) \
	buffer_alloc_put_(BUFFER_FORMAT(__VA_ARGS__))

#define buffer_put(b, ...) \
	buffer_put_(b, BUFFER_FORMAT(__VA_ARGS__))

#define buffer_get(b, ...) \
	buffer_get_(b, BUFFER_FORMAT(__VA_ARGS__))


typedef struct buffer *buffer_t;

extern buffer_t buffer_alloc(size_t size_estimate);
extern buffer_t buffer_init(const uint8_t *data, size_t data_length);
extern buffer_t buffer_alloc_put_(const struct buffer_description *data);
extern void buffer_free(buffer_t b);
extern void buffer_give_up(buffer_t *b, uint8_t **data, size_t *data_length);

extern int buffer_put_uint16(buffer_t b, uint16_t data);
extern int buffer_put_uint16_ascii(buffer_t b, uint16_t data);
extern int buffer_put_bytes(buffer_t b, const uint8_t *data, size_t data_length);
extern int buffer_put_mpz(buffer_t b, mpz_t data);
extern int buffer_put_mpz_ascii(buffer_t b, mpz_t data);
extern int buffer_put_(buffer_t b, const struct buffer_description *data);

extern int buffer_get_uint16(buffer_t b, uint16_t *data);
extern int buffer_get_uint16_ascii(buffer_t b, uint16_t *data);
extern int buffer_get_bytes(buffer_t b, uint8_t const **data, size_t data_length);
extern int buffer_get_mpz(buffer_t b, mpz_t data);
extern int buffer_get_mpz_ascii(buffer_t b, mpz_t data);
extern int buffer_get_(buffer_t b, const struct buffer_description *data);


#endif /* BUFFER_H_ */
