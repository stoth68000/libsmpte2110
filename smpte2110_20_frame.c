/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#include "smpte2110.h"

struct smpte2110_20_frame_s *smpte2110_20_frame_alloc()
{
	struct smpte2110_20_frame_s *frame = malloc(sizeof(*frame));
	return frame;
}

void smpte2110_20_frame_free(struct smpte2110_20_frame_s *frame)
{
	free(frame);
}

void smpte2110_20_frame_dump(struct smpte2110_20_frame_s *frame)
{
}

