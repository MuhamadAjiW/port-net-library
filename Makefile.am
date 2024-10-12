ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src/lib @EXTRA_TARGETS@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndpi.pc

EXTRA_DIST = README.md README.fuzzer.md CHANGELOG.md CONTRIBUTING.md \
	autogen.sh utils packages \
	influxdb/Makefile.in influxdb/metric_anomaly.c influxdb/README.txt \
	lists/100_malware.list \
	lists/107_gambling.list \
	lists/107_gambling_custom.list \
	lists/public_suffix_list.dat \
	lists/README.md

coverage: all
	mkdir -vp coverage_report/ndpi_coverage_report
	lcov --directory . --capture --output-file lcov.info
	genhtml -o coverage_report/ndpi_coverage_report lcov.info

clean-coverage:
	rm -f lcov.info
	find . -type f -name "*.gcda" -exec rm "{}" +
	find . -type f -name "*.gcno" -exec rm "{}" +

changelog:
	git log --since={`curl -s https://github.com/ntop/ndpi/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" | grep  "^ " > CHANGELOG.latest

.PHONY: coverage clean-coverage changelog
