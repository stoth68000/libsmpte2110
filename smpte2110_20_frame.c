/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#include "smpte2110.h"

struct smpte2110_20_frame_s *smpte2110_20_frame_alloc(int64_t nr, int width, int height, int cs, int strideBytes)
{
	struct smpte2110_20_frame_s *frame = malloc(sizeof(*frame));

	frame->nr = nr;
#if 0
	frame->cs = cs;
	frame->width = width;
	frame->height = height;
#endif
	frame->strideBytes = strideBytes;
	frame->lengthBytes = strideBytes * height;
	frame->ptr = malloc(frame->lengthBytes);

	return frame;
}

void smpte2110_20_frame_free(struct smpte2110_20_frame_s *frame)
{
	free(frame->ptr);
	free(frame);
}

int smpte2110_20_frame_save(struct smpte2110_20_frame_s *frame)
{
	char fn[64];
	sprintf(fn, "frame-%08" PRIi64 ".yuv", frame->nr);

	printf("%s() saving frame as '%s'\n", __func__, fn);
	FILE *fh = fopen(fn, "wb");
	if (fh) {
		fwrite(frame->ptr, 1, frame->lengthBytes, fh);
		fclose(fh);
	}

	return 0;
}

void smpte2110_20_frame_dump(struct smpte2110_20_frame_s *frame)
{
}

/* Copy the data to 'line' at the relevant 'offset' */
static int smpte2110_20_write_packet_line(struct smpte2110_20_frame_s *frame, struct smpte2110_20_packet_line_s *line)
{
	unsigned char *dst = frame->ptr;
	dst += (line->SRD_Row_Number * frame->strideBytes);
	dst += ((line->SRD_Offset / 2) * 5);

	memcpy(dst, line->data, line->SRD_Length);

	return 0;
}

int smpte2110_20_frame_packet_write(struct smpte2110_20_frame_s *frame, struct smpte2110_20_packet_s *pkt)
{
	int ret = 0;
	for (int i = 0; i < pkt->Line_Count; i++) {
		ret += smpte2110_20_write_packet_line(frame, &pkt->array[i]);
	}

	return 0;
}

