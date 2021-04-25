/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smpte2110.h"

struct smpte2110_20_receiver_element_s *smpte2110_20_receiver_element_alloc()
{
        struct smpte2110_20_receiver_element_s *element = malloc(sizeof(*element));
	return element;
};

struct smpte2110_20_receiver_s *smpte2110_20_receiver_alloc()
{
	struct smpte2110_20_receiver_s *ctx = malloc(sizeof(*ctx));
	ctx->bs = klbs_alloc();
	xorg_list_init(&ctx->listElements);

	return ctx;
}

void smpte2110_20_receiver_free(struct smpte2110_20_receiver_s *ctx)
{
	/* TODO: Free the entire list */
	klbs_free(ctx->bs);
	free(ctx);
}

void smpte2110_20_receiver_dump(struct smpte2110_20_receiver_s *ctx)
{
	/* TODO: dump the entire list */
}

int smpte2110_20_receiver_write(struct smpte2110_20_receiver_s *ctx, const unsigned char *buf, int lengthBytes)
{
	struct smpte2110_20_receiver_element_s *element = smpte2110_20_receiver_element_alloc();
	smpte2110_20_packet_parse(&element->pkt, ctx->bs, buf, lengthBytes);

	if (!element->pkt) {
		free(element);
		return -1;
	}

	return 0;
}

