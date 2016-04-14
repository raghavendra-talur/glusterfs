xlator_LTLIBRARIES = sr.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

sr_la_LDFLAGS = -module $(GF_XLATOR_DEFAULT_LDFLAGS)

sr_la_SOURCES = share-reservation.c
sr_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = share-reservation.h share-reservation-messages.h \
		 share-reservation-mem-types.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES =
