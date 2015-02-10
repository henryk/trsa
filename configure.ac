dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libtrsa, 0.1)
AC_PROG_CC

AC_CANONICAL_SYSTEM

dnl Initialize automake
AM_INIT_AUTOMAKE

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O
AC_PROG_CC_C99

dnl Initialize Libtool
LT_INIT

dnl Check if Libtool is present
dnl Libtool is used for building share libraries 
AC_PROG_LIBTOOL

AC_CHECK_LIB(gmp, __gmpz_init, ,
       [AC_MSG_ERROR([GNU MP not found, see https://gmplib.org/])])

#### Find OpenSSL
AC_MSG_CHECKING([for --with-openssl])
AC_ARG_WITH(
	[openssl],
	[AS_HELP_STRING([--with-openssl],[/absolute/path/to/openssl-base])],
	[ LDFLAGS="$LDFLAGS -L$with_openssl/lib";
	  CFLAGS="$CFLAGS -I$with_openssl/include/";
	  LIBS="-lssl";
	  AC_MSG_RESULT([$with_openssl])
	],
	[AC_MSG_RESULT([no])]
)

AC_CHECK_LIB([crypto],[PKCS5_PBKDF2_HMAC], [], [AC_MSG_ERROR([OpenSSL libraries required])])

AC_CHECK_HEADERS([openssl/evp.h],[],[AC_MSG_ERROR([OpenSSL headers required])])


AC_CONFIG_FILES(Makefile
                examples/Makefile
                libtrsa/Makefile
                include/Makefile)
AC_OUTPUT