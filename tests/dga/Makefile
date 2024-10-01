CC=gcc
CXX=g++
EXE_SUFFIX=

SRCHOME=../../src

ifneq ($(OS),Windows_NT)
CFLAGS+=-fPIC -DPIC
endif
CFLAGS+=-g -I$(SRCHOME)/include -W -Wall -Wno-address-of-packed-member  -D_DEFAULT_SOURCE=1 -D_GNU_SOURCE=1 -O2 -DUSE_GLOBAL_CONTEXT
LIBNDPI=$(SRCHOME)/lib/libndpi.a
LIBS=$(LIBNDPI) -lm -lpthread -lpthread 
LDFLAGS+=
HEADERS=$(SRCHOME)/include/ndpi_api.h $(SRCHOME)/include/ndpi_typedefs.h $(SRCHOME)/include/ndpi_protocol_ids.h
OBJS=dga_evaluate
PREFIX?=/usr

all: dga_evaluate$(EXE_SUFFIX)

EXECUTABLE_SOURCES := dga_evaluate.c
COMMON_SOURCES := $(filter-out $(EXECUTABLE_SOURCES),$(wildcard *.c ))

dga_evaluate$(EXE_SUFFIX): $(LIBNDPI) dga_evaluate.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) dga_evaluate.o $(LIBS) -o $@

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	/bin/rm -f *.o dga_evaluate$(EXE_SUFFIX)
	/bin/rm -f .*.o.cmd .*.o.d
	/bin/rm -rf build

install:
	echo ""

distdir:

distclean: clean
	/bin/rm -f Makefile

check:
	true # nothing to do here, done by invoking tests/do-dga.sh
