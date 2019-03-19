AC_INIT(fido2-ctap-gadget, 0.0.1, <James.Bottomley@HansenPartnership.com>)
AM_INIT_AUTOMAKE([foreign 1.6])

AC_CHECK_PROGS([HELP2MAN], [help2man])

AC_LANG(C)
AC_PROG_CC_STDC
AC_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

PKG_CHECK_MODULES([CRYPTO], [libcrypto]);

AC_SEARCH_LIBS([TSS_Create], [tss ibmtss], [], [
	AC_MSG_ERROR([Unable to find the TSS2 library])
])

CPPFLAGS="$CPPFLAGS -DTPM_POSIX"
AC_CHECK_HEADER([/usr/include/tss2/tss.h],[TSSINCLUDE=/usr/include/tss2],
	AC_CHECK_HEADER([/usr/include/ibmtss/tss.h],[TSSINCLUDE=/usr/include/ibmtss],
	   AC_MSG_ERROR([No TSS2 include directory found])))
AC_SUBST([TSSINCLUDE])

AC_OUTPUT([Makefile])
