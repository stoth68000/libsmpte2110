/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#ifndef SMPTE2110_20_H
#define SMPTE2110_20_H

#include <stdint.h>

/* https://tools.ietf.org/html/smpte2110_20 */
struct smpte2110_20_line_s
{
	uint32_t SRD_Length;
	uint32_t F;
	uint32_t SRD_Row_Number;
	uint32_t C;
	uint32_t SRD_Offset;
};

struct smpte2110_20_s
{
	uint16_t ExtendedSequenceNumber;
	uint16_t Line_Count;
	struct smpte2110_20_line_s *array;
};

struct smpte2110_20_s *smpte2110_20_alloc();
void smpte2110_20_free(struct smpte2110_20_s *p);
void smpte2110_20_dump(struct smpte2110_20_s *rfchdr);

struct klbs_context_s;
int smpte2110_20_parse(struct smpte2110_20_s **p, struct klbs_context_s *bs, const unsigned char *buf, int lengthBytes);

#endif /* SMPTE2110_20_H */
