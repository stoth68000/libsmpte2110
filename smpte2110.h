#ifndef KL_SMPTE2110_H
#define KL_SMPTE2110_H

/* Nomanclature / terminology / objects:
 *
 * struct rtp_hdr_analyzer_s          - 
 * struct smpte2110_20_packet_s       - A container for a single RTP packet, may contain 0-many packet_line_s.
 * struct smpte2110_20_packet_line_s  - Container exclusively within a smpte2110_20_packet_
 * struct smpte2110_20_frame_s        - A full assembled video frame, emiited from the receiver object.
 * struct smpte2110_20_receiver_s     - Helper. Parse RTP streams, assemble packets and emit video frames.
 *
 * callbacks:
 *  typedef void (*smpte2110_20_frame_arrival)(void *userContext, struct smpte2110_20_frame_s *frame);
 *
 *
 */
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

#endif /* KL_SMPTE2110_H */
