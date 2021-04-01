
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

CFLAGS  = -Wall --std=c99 -D_BSD_SOURCE -DGIT_VERSION=\"$(GIT_VERSION)\" 
LDFLAGS = -lpcap

smpte2110-40-analyzer:	smpte2110-40-analyzer.c rtp.h rfc8331.h rfc8331.c copyright.h
	gcc $(CFLAGS) $(@).c rfc8331.c $(LDFLAGS) -o smpte2110-40-analyzer

clean:
	rm -f smpte2110-40-analyzer
