bin_PROGRAMS=fido hidgd

man1_MANS=hidgd.1

fido_SOURCES=fido.c

hidgd_SOURCES=hidgd.c u2f.h u2f_hid.h

AM_CFLAGS=-Wall -Werror

$(builddir)/%.1: $(srcdir)/%.1.in $(top_builddir)/%
	$(HELP2MAN) --no-info -i $< -o $@ $(top_builddir)/$*
