CC=gcc
CXX=g++
BUILD_MINGW=
EXE_SUFFIX=

SRCHOME=../../src

ifneq ($(OS),Windows_NT)
CFLAGS+=-fPIC -DPIC
endif
CFLAGS+=-g -I$(SRCHOME)/include -W -Wall -Wno-address-of-packed-member  -D_DEFAULT_SOURCE=1 -D_GNU_SOURCE=1 -O2 -DUSE_GLOBAL_CONTEXT -I/usr/include/json-c 
LIBNDPI=$(SRCHOME)/lib/libndpi.a
LIBS=$(LIBNDPI) -lpcap -lm -ljson-c -lpthread 
LDFLAGS+=
HEADERS=$(SRCHOME)/include/ndpi_api.h $(SRCHOME)/include/ndpi_typedefs.h $(SRCHOME)/include/ndpi_protocol_ids.h
OBJS=unit
PREFIX?=/usr

ifneq ($(BUILD_MINGW),)

ifeq ($(DISABLE_NPCAP),0)
CFLAGS+=-I./../windows/WpdPack/Include -I./../windows/WpdPack/Include/pcap
else
CFLAGS+=-DDISABLE_NPCAP
endif

ifeq ($(DISABLE_NPCAP),0)

ifneq ($(BUILD_MINGW_X64),)
LIBS+=./../windows/WpdPack/Lib/x64/wpcap.lib
else
LIBS+=./../windows/WpdPack/Lib/wpcap.lib
endif

endif

LIBS+=-Wl,-Bstatic -lpthread -Wl,-Bdynamic
else
LIBS+=-pthread
endif

all: unit$(EXE_SUFFIX)

EXECUTABLE_SOURCES := unit.c
COMMON_SOURCES := $(filter-out $(EXECUTABLE_SOURCES),$(wildcard *.c ))

unit$(EXE_SUFFIX): $(LIBNDPI) unit.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) unit.o $(LIBS) -o $@

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	/bin/rm -f *.o unit$(EXE_SUFFIX)
	/bin/rm -f .*.o.cmd .*.o.d
	/bin/rm -rf build

install:
	echo ""

distdir:

distclean: clean
	/bin/rm -f Makefile

check:
	true # nothing to do here, done by invoking tests/do-unit.sh
