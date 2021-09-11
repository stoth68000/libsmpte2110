/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#ifndef SMPTE2110_20_FRAME_H
#define SMPTE2110_20_FRAME_H

#include "smpte2110.h"

struct smpte2110_20_frame_s
{
	int64_t nr;

//	int width;
//	int height;
//	int cs;

	int lengthBytes;
	int strideBytes;

	unsigned char *ptr;	
};

struct smpte2110_20_frame_s *smpte2110_20_frame_alloc(int64_t nr, int width, int height, int cs, int strideBytes);

int  smpte2110_20_frame_packet_write(struct smpte2110_20_frame_s *frame, struct smpte2110_20_packet_s *pkt);

void smpte2110_20_frame_free(struct smpte2110_20_frame_s *ctx);
void smpte2110_20_frame_dump(struct smpte2110_20_frame_s *ctx);
int  smpte2110_20_frame_save(struct smpte2110_20_frame_s *ctx);

#endif /* SMPTE2110_20_FRAME_H */
