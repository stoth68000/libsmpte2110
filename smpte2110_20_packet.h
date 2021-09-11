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
	/* See SMPTE ST 2110-20:2017 6.1.4 */
	uint32_t SRD_Length;     /* Sample Rows Data */
	uint32_t F;		 /* Field Identification bit.
				  * Progresive always 0. For PsF see spec.
				  * Interlaced is 0 = first field, 1 = second field.
				  */
	uint32_t SRD_Row_Number; /* Progressize starts at 0 at the top of the frame.
				  * Interaced starts at 0 at the top of each field.
				  * 1280x720p would therefore contain 0..719
				  */
	uint32_t C;		 /* True if additional data for this row is in a following RTP frame. */
	uint32_t SRD_Offset;	 /* Sample Position of the first sample in the associated Sample Row Data Segment */

	unsigned char *data;	 /* Raw network data, in whatever colorspace and packing format. */
};

/* Each packet contains multiple lines.
 * Packets can contain pixels for multiple frame lines.
 */
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
