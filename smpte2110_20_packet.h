/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#ifndef SMPTE2110_20_PACKET_H
#define SMPTE2110_20_PACKET_H

#include <stdint.h>

/* In the RTP world, messages will arrive that we'll need to
 * de-serialize into in-memory structs. This object represents
 * a single RTP frame and all of its associated lines.
 */
struct smpte2110_20_packet_line_s
{
	uint32_t SRD_Length;
	uint32_t F;
	uint32_t SRD_Row_Number;
	uint32_t C;
	uint32_t SRD_Offset;
};

struct smpte2110_20_packet_s
{
	uint16_t ExtendedSequenceNumber;
	uint16_t Line_Count;
	struct smpte2110_20_packet_line_s *array;
};

struct smpte2110_20_packet_s *smpte2110_20_packet_alloc();
void smpte2110_20_packet_free(struct smpte2110_20_packet_s *p);
void smpte2110_20_packet_dump(struct smpte2110_20_packet_s *rfchdr);

struct klbs_context_s;
int smpte2110_20_packet_parse(struct smpte2110_20_packet_s **p, struct klbs_context_s *bs, const unsigned char *buf, int lengthBytes);

#endif /* SMPTE2110_20_PACKET_H */
