#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>

#if __linux
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#endif

#include "rtp.h"
#include "klbitstream_readwriter.h"
#include "smpte2110_20_packet.h"
#include "smpte2110_20_receiver.h"
#include "smpte2110_20_frame.h"
