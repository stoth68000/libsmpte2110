
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

CFLAGS  = -Wall --std=c99 -D_BSD_SOURCE -DGIT_VERSION=\"$(GIT_VERSION)\" 
LDFLAGS = -lpcap

all:	smpte2110-20-analyzer smpte2110-40-analyzer

smpte2110-20-analyzer:	xorg-list.h smpte2110-20-analyzer.c rtp.h rfc8331.h rfc8331.c smpte2110_20.h smpte2110_20.c copyright.h
	gcc $(CFLAGS) $(@).c rfc8331.c smpte2110_20.c $(LDFLAGS) -o smpte2110-20-analyzer

smpte2110-40-analyzer:	xorg-list.h smpte2110-40-analyzer.c rtp.h rfc8331.h rfc8331.c smpte2110_20.h smpte2110_20.c copyright.h
	gcc $(CFLAGS) $(@).c rfc8331.c smpte2110_20.c $(LDFLAGS) -o smpte2110-40-analyzer

clean:
	rm -f smpte2110-20-analyzer smpte2110-40-analyzer

pcapcapture:
	sudo tcpdump -i enp2s0f0 -w /tmp/capture.pcap -B 65536 -s 256000
