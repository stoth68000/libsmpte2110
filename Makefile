
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

CFLAGS   = -Wall --std=c99 -D_BSD_SOURCE -DGIT_VERSION=\"$(GIT_VERSION)\"  -g
CFLAGS  += -I../sdp_parser
LDFLAGS  = -lpcap
LDFLAGS += -L../sdp_parser -lsdp

CORE_OBJS = smpte2110_20_receiver.o smpte2110_20_frame.o smpte2110_20_packet.o

all:	core smpte2110-20-analyzer smpte2110-40-analyzer

core:	$(CORE_OBJS)

smpte2110_20_packet.o:	smpte2110_20_packet.h smpte2110_20_packet.c
	gcc $(CFLAGS) -c smpte2110_20_packet.c -o $(@)

smpte2110_20_receiver.o:	smpte2110_20_receiver.h smpte2110_20_receiver.c
	gcc $(CFLAGS) -c smpte2110_20_receiver.c -o $(@)

smpte2110_20_frame.o:	smpte2110_20_frame.h smpte2110_20_frame.c
	gcc $(CFLAGS) -c smpte2110_20_frame.c -o $(@)

smpte2110-20-analyzer:	xorg-list.h smpte2110-20-analyzer.c rtp.h rfc8331.h rfc8331.c core copyright.h
	gcc $(CFLAGS) $(@).c rfc8331.c $(CORE_OBJS) $(LDFLAGS) -o smpte2110-20-analyzer

smpte2110-40-analyzer:	xorg-list.h smpte2110-40-analyzer.c rtp.h rfc8331.h rfc8331.c core copyright.h
	gcc $(CFLAGS) $(@).c rfc8331.c $(CORE_OBJS) $(LDFLAGS) -o smpte2110-40-analyzer

clean:
	rm -f smpte2110-20-analyzer smpte2110-40-analyzer *.o

pcapcapture:
	sudo tcpdump -i enp2s0f0 -w /tmp/capture.pcap -B 65536 -s 256000
