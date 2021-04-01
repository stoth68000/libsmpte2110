/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#include "rfc8331.h"

#include "klbitstream_readwriter.h"

#define SANITIZE(n) ((n) & 0xff)

struct rfc8331_s *rfc8331_alloc()
{
	struct rfc8331_s *p = malloc(sizeof(*p));
	return p;
}

void rfc8331_free(struct rfc8331_s *p)
{
	if (p) {
		if (p->array) {
			free(p->array);
		}
		free(p);
	}
}

int rfc8331_parse(struct rfc8331_s **p, struct klbs_context_s *bs, const unsigned char *rtpdata, int rtpdatalen)
{
	struct rfc8331_s *rfchdr = rfc8331_alloc();
	*p = rfchdr;

	klbs_read_set_buffer(bs, (unsigned char *)rtpdata, rtpdatalen);

	rfchdr->ExtendedSequenceNumber = klbs_read_bits(bs, 16);
	rfchdr->Length                 = klbs_read_bits(bs, 16);
	rfchdr->ANC_Count              = klbs_read_bits(bs, 8);
	rfchdr->F                      = klbs_read_bits(bs, 2);
	klbs_read_bits(bs, 22); /* Reserved */
	if (rfchdr->ANC_Count == 0) {
		rfchdr->array = NULL;
		return 0;
	}

	rfchdr->array = malloc(rfchdr->ANC_Count * sizeof(struct rfc8331_line_s));

	for (int j = 0; j < rfchdr->ANC_Count; j++) {
		struct rfc8331_line_s *l = &rfchdr->array[j];
		l->C                 = klbs_read_bits(bs, 1);
		l->Line_Number       = klbs_read_bits(bs, 11);
		l->Horizontal_Offset = klbs_read_bits(bs, 12);
		l->S                 = klbs_read_bits(bs, 1);
		l->StreamNum         = klbs_read_bits(bs, 7);
		l->DID               = klbs_read_bits(bs, 10);
		l->SDID              = klbs_read_bits(bs, 10);
		l->Data_Count        = klbs_read_bits(bs, 10);

		for (int i = 0; i < SANITIZE(l->Data_Count); i++) {
			l->Data[i] = klbs_read_bits(bs, 10);
		}
		l->Checksum_Word = klbs_read_bits(bs, 10);
	}

	return 0;
}

void rfc8331_dump(struct rfc8331_s *rfchdr)
{
	printf("extended SN: %04x\n", rfchdr->ExtendedSequenceNumber);
	printf("Length     : 0x%02x\n", rfchdr->Length);
	printf("ANC_Count  : 0x%02x\n", rfchdr->ANC_Count);
	printf("F          : 0x%02x\n", rfchdr->F);

	for (int j = 0; j < rfchdr->ANC_Count; j++) {
		struct rfc8331_line_s *l = &rfchdr->array[j];
		printf("C          : 0x%02x\n", l->C);
		printf("Line       : 0x%04x\n", l->Line_Number);
		printf("H/Offset   : 0x%04x\n", l->Horizontal_Offset);
		printf("S          : 0x%02x\n", l->S);
		printf("StreamNum  : 0x%02x\n", l->StreamNum);
		printf("DID        : 0x%04x\n", l->DID);
		printf("SDID       : 0x%04x\n", l->SDID);
		printf("Data_Count : 0x%04x\n", l->Data_Count);
		printf("    ");
		for (int i = 1; i <= SANITIZE(l->Data_Count); i++) {
			printf("%04x ", l->Data[i - 1]);
			if (i % 16 == 0)
				printf("\n    ");
		}
		printf("\n    checksum %04x\n", l->Checksum_Word);
	}
}
