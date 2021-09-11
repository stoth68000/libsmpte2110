/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

/* Framework to parse 2110-20 Video packets and do interesting things with them,
 * such as converting them to/from actual video frames.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#include "smpte2110_20_packet.h"

#include "klbitstream_readwriter.h"

struct smpte2110_20_packet_s *smpte2110_20_packet_alloc()
{
	struct smpte2110_20_packet_s *p = malloc(sizeof(*p));
	return p;
}

void smpte2110_20_packet_free(struct smpte2110_20_packet_s *pkt)
{
	if (pkt) {
		if (pkt->array) {
			for (int i = 0; i < pkt->Line_Count; i++) {
				struct smpte2110_20_packet_line_s *l = &pkt->array[i];
				if (l->data) {
					free(l->data);
				}
			}
			free(pkt->array);
		}
		free(pkt);
	}
}

int smpte2110_20_packet_parse(struct smpte2110_20_packet_s **p, struct klbs_context_s *bs,
	const unsigned char *rtpdata, int rtpdatalen)
{
	struct smpte2110_20_packet_s *rfchdr = smpte2110_20_packet_alloc();
	*p = rfchdr;

	klbs_read_set_buffer(bs, (unsigned char *)rtpdata, rtpdatalen);

	rfchdr->ExtendedSequenceNumber = klbs_read_bits(bs, 16);
	rfchdr->Line_Count = 12;

	rfchdr->array = malloc(rfchdr->Line_Count * sizeof(struct smpte2110_20_packet_line_s));
	if (!rfchdr->array) {
		smpte2110_20_packet_free(rfchdr);
		return -1;
	}

	int j = 0;
	int i = 2;
	while (1) {
		struct smpte2110_20_packet_line_s *l = &rfchdr->array[j];
#if 1
		l->SRD_Length     = rtpdata[i] << 8 | rtpdata[i + 1];
		if (l->SRD_Length == 0)
			break;

		if (i + l->SRD_Length > rtpdatalen)
			break;

		l->F              = rtpdata[i + 2] & 0x80 ? 1 : 0;
		l->SRD_Row_Number = (rtpdata[i + 2] << 8 | rtpdata[i + 3]) & 0x7fff;
		l->C              = rtpdata[i + 4] & 0x80 ? 1 : 0;
		l->SRD_Offset     = (rtpdata[i + 4] << 8 | rtpdata[i + 5]) & 0x7fff;

		l->data           = malloc(l->SRD_Length);
		memcpy(l->data, &rtpdata[i + 6], l->SRD_Length);
		/* CSC */
		for (int z = 0; z < l->SRD_Length; z += 5) {
			unsigned int y0  = (l->data[ z + 1 ] & 0x3f) << 4;
			             y0 |= (l->data[ z + 2 ] & 0xf0) >> 4;
			unsigned int y1  = (l->data[ z + 3 ] & 0x03) << 8;
			             y1 |= (l->data[ z + 4 ]);
			unsigned int c0  = l->data[ z + 0 ] << 2;
			             c0 |= (l->data[ z + 1 ] & 0xc0) >> 6;
			unsigned int c1  = (l->data[ z + 2 ] & 0x0f) << 6;
			             c1 |= (l->data[ z + 3 ] & 0xfc) >> 2;

#if 1
	/* YCRY */
			l->data[z + 0]  = c0 >> 2;
			l->data[z + 1]  = (c0 & 0x03) << 6;
			l->data[z + 1] |= (y0 >> 4);
			l->data[z + 2] &= 0x0f;
			l->data[z + 2] |= (y0 & 0x0f) << 4;
#endif

		}

		i += (6 + l->SRD_Length);

		j++;
#else
		l->SRD_Length            = klbs_read_bits(bs, 16);
		if (l->SRD_Length == 0)
			break;
		if (l->SRD_Length > klbs_get_buffer_size(bs) - klbs_get_byte_count(bs)) {
			break;
		}
		l->F                     = klbs_read_bits(bs, 1);
		l->SRD_Row_Number        = klbs_read_bits(bs, 15);
		l->C                     = klbs_read_bits(bs, 1);
		l->SRD_Offset            = klbs_read_bits(bs, 15);

		l->data                  = malloc(l->SRD_Length);
		for (int j = 0; j < l->SRD_Length; j++)
			l->data[j] = klbs_read_byte_aligned(bs);

		j++;

		if (klbs_get_byte_count(bs) + 6 > klbs_get_buffer_size(bs)) {
			break;
		}
#endif
	}
	rfchdr->Line_Count = j;

	return 0;
}

void smpte2110_20_packet_dump(struct smpte2110_20_packet_s *rfchdr)
{
	printf("%s(%p)\n", __func__, rfchdr);
	printf("  extended SN: %04x\n", rfchdr->ExtendedSequenceNumber);
	printf("  Line_Count : 0x%02x\n", rfchdr->Line_Count);

	for (int j = 0; j < rfchdr->Line_Count; j++) {
		struct smpte2110_20_packet_line_s *l = &rfchdr->array[j];
		printf("    SRD_Length     : %05d  ", l->SRD_Length);
		printf("    F              : %d  ", l->F);
		printf("    SRD_Line_No    : %04d  ", l->SRD_Row_Number);
		printf("    C              : %d  ", l->C);
		printf("    SRD_Offset     : %05d\n", l->SRD_Offset);
	}
}
