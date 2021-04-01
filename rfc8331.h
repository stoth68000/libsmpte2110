/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#ifndef RFC8331_H
#define RFC8331_H

#include <stdint.h>

/* https://tools.ietf.org/html/rfc8331 */
struct rfc8331_line_s
{
	uint32_t C;
	uint32_t Line_Number;
	uint32_t Horizontal_Offset;
	uint32_t S;
	uint32_t StreamNum;
	uint32_t DID;
	uint32_t SDID;
	uint32_t Data_Count;
	uint16_t Data[256];
	uint16_t Checksum_Word;
};

struct rfc8331_s
{
	uint16_t ExtendedSequenceNumber;
	uint16_t Length;
	uint16_t ANC_Count;
	uint32_t F;
	struct rfc8331_line_s *array;
};

struct rfc8331_s *rfc8331_alloc();
void rfc8331_free(struct rfc8331_s *p);
void rfc8331_dump(struct rfc8331_s *rfchdr);

struct klbs_context_s;
int rfc8331_parse(struct rfc8331_s **p, struct klbs_context_s *bs, const unsigned char *buf, int lengthBytes);

#endif /* RFC8331_H */
