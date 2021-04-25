/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#ifndef SMPTE2110_20_FRAME_H
#define SMPTE2110_20_FRAME_H

#include "smpte2110.h"

struct smpte2110_20_frame_s
{
	int nr;
};

struct smpte2110_20_frame_s *smpte2110_20_frame_alloc();
void smpte2110_20_frame_free(struct smpte2110_20_frame_s *ctx);
void smpte2110_20_frame_dump(struct smpte2110_20_frame_s *ctx);

#endif /* SMPTE2110_20_FRAME_H */
