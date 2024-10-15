ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src/lib @EXTRA_TARGETS@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndpi.pc

EXTRA_DIST = README.md \
	autogen.sh utils packages \
	lists/100_malware.list \
	lists/107_gambling.list \
	lists/107_gambling_custom.list \
	lists/public_suffix_list.dat \
	lists/README.md \
	.github

coverage: all
	mkdir -vp coverage_report/ndpi_coverage_report
	lcov --directory . --capture --output-file lcov.info
	genhtml -o coverage_report/ndpi_coverage_report lcov.info

clean-coverage:
	rm -f lcov.info
	find . -type f -name "*.gcda" -exec rm "{}" +
	find . -type f -name "*.gcno" -exec rm "{}" +

.PHONY: coverage clean-coverage
