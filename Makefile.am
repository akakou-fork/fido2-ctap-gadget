bin_PROGRAMS=fido hidgd

man1_MANS=hidgd.1

fido_SOURCES=fido.c

AM_CFLAGS=-Wall -Werror

hidgd_SOURCES=hidgd.c u2f.h u2f_hid.h tpm.c hidgd-tpm.h
hidgd_CFLAGS=-I@TSSINCLUDE@ ${CRYPTO_CFLAGS} ${AM_CFLAGS}
hidgd_LDADD=${CRYPTO_LIBS}


$(builddir)/%.1: $(srcdir)/%.1.in $(top_builddir)/%
	$(HELP2MAN) --no-info -i $< -o $@ $(top_builddir)/$*
