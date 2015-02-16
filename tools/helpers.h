/*
 * helpers.h
 *
 *  Created on: 16 Feb 2015
 *      Author: henryk
 */

#ifndef HELPERS_H_
#define HELPERS_H_

#include <stdint.h>

#define CHECK_( exp, label ) do { if(!(exp)) { fputs(label " failed. Aborting.\n", stderr); goto abort;} } while(0)
#define CHECK_EXP(exp) CHECK_( exp, #exp )
#define CHECK_RETVAL(exp) CHECK_( (exp) >= 0, #exp )

extern int read_data(uint8_t **data, size_t *data_length, const char *format, ...);
extern int write_data(const uint8_t *data, size_t data_length, const char *format, ...);

#endif /* HELPERS_H_ */
