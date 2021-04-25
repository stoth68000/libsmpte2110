/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#include "smpte2110_20.h"

#include "klbitstream_readwriter.h"

#define SANITIZE(n) ((n) & 0xff)

struct smpte2110_20_s *smpte2110_20_alloc()
{
	struct smpte2110_20_s *p = malloc(sizeof(*p));
	return p;
}

void smpte2110_20_free(struct smpte2110_20_s *p)
{
	if (p) {
		if (p->array) {
			free(p->array);
		}
		free(p);
	}
}

int smpte2110_20_parse(struct smpte2110_20_s **p, struct klbs_context_s *bs, const unsigned char *rtpdata, int rtpdatalen)
{
printf("rtplen %d bytes\n", rtpdatalen);
	struct smpte2110_20_s *rfchdr = smpte2110_20_alloc();
	*p = rfchdr;

	klbs_read_set_buffer(bs, (unsigned char *)rtpdata, rtpdatalen);

	rfchdr->ExtendedSequenceNumber = klbs_read_bits(bs, 16);
	rfchdr->Line_Count = 12;

	rfchdr->array = malloc(rfchdr->Line_Count * sizeof(struct smpte2110_20_line_s));

	int j = 0;
	while (1) {
		struct smpte2110_20_line_s *l = &rfchdr->array[j];
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
		for (int j = 0; j < l->SRD_Length; j++)
			klbs_read_byte_aligned(bs);

		j++;

		if (klbs_get_byte_count(bs) + 6 > klbs_get_buffer_size(bs)) {
			break;
		}
	}
	rfchdr->Line_Count = j;

	return 0;
}

void smpte2110_20_dump(struct smpte2110_20_s *rfchdr)
{
	printf("extended SN: %04x\n", rfchdr->ExtendedSequenceNumber);
	printf("Line_Count : 0x%02x\n", rfchdr->Line_Count);

	for (int j = 0; j < rfchdr->Line_Count; j++) {
		struct smpte2110_20_line_s *l = &rfchdr->array[j];
		printf("SRD_Length     : 0x%04x  ", l->SRD_Length);
		printf("F              : %d  ", l->F);
		printf("SRD_Line_No    : 0x%04x  ", l->SRD_Row_Number);
		printf("C              : %d  ", l->C);
		printf("SRD_Offset     : 0x%04x\n", l->SRD_Offset);
	}
}
