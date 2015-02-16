/*
 * helpers.c
 *
 *  Created on: 16 Feb 2015
 *      Author: henryk
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "helpers.h"

int read_data(uint8_t **data, size_t *data_length, const char *format, ...)
{
	int retval = -1;
	char *name = NULL;
	FILE *fp = NULL;
	va_list a;

	if(!data || !format) {
		return -1;
	}

	*data = NULL;

	va_start(a, format);
	int r = vasprintf(&name, format, a);
	va_end(a);

	if(r < 0) {
		name = NULL;
		goto abort;
	}

	fp = fopen(name, "rb");
	if(!fp) {
		fprintf(stderr, "Couldn't open %s. Aborting.\n", name);
		goto abort;
	}

	if( fseek(fp, 0, SEEK_END) ) {
		fprintf(stderr, "Couldn't seek to end of file. Aborting.\n");
		goto abort;
	}
	long fsize = ftell(fp);
	if(fsize < 0) {
		fprintf(stderr, "Couldn't get file length. Aborting.\n");
		goto abort;
	}
	if( fseek(fp, 0, SEEK_SET) < 0) {
		fprintf(stderr, "Couldn't seek to start of file. Aborting.\n");
		goto abort;
	}

	*data_length = fsize;
	*data = malloc(*data_length);
	if(!*data) {
		fprintf(stderr, "Couldn't allocate memory. Aborting.\n");
		goto abort;
	}

	if( fread(*data, 1, *data_length, fp) != *data_length ) {
		fprintf(stderr, "Couldn't read from %s. Aborting.\n", name);
		goto abort;
	}

	retval = 0;

abort:
	free(name);
	if(fp) {
		fclose(fp);
	}
	if(retval < 0) {
		free(*data);
		*data = NULL;
	}
	return retval;
}

int write_data(const uint8_t *data, size_t data_length, const char *format, ...)
{
	int retval = -1;
	char *name = NULL;
	FILE *fp = NULL;
	va_list a;

	if(!data || !format) {
		return -1;
	}

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

