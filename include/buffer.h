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

struct buffer {
	uint8_t *d;
	size_t l;
	size_t p;
};

typedef struct buffer *buffer_t;

extern buffer_t buffer_alloc(size_t size_estimate);
extern void buffer_free(buffer_t b);
extern void buffer_give_up(buffer_t *b, uint8_t **data, size_t *data_length);

extern int buffer_put_uint16(buffer_t b, uint16_t data);
extern int buffer_put_bytes(buffer_t b, const uint8_t *data, size_t data_length);


#endif /* BUFFER_H_ */
