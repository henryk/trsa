bin_PROGRAMS=trsadeal trsaenc

# Sources
trsadeal_SOURCES= trsadeal.c helpers.c
trsaenc_SOURCES= trsaenc.c helpers.c

# Linker options
AM_LDFLAGS = $(top_srcdir)/libtrsa/libtrsa.la

# Compiler options
AM_CPPFLAGS = -Wall -pedantic -Werror -I$(top_srcdir)/include
