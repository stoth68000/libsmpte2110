/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smpte2110.h"

/* A video frame element is made up of many RTP packets.
 * This structs contains a denormalized RTP packet, including fragments
 * or pixels. We'll put these into a list ordered by arrival time
 * and reference them later in order to create a final video frame.
 */
struct smpte2110_20_receiver_element_s
{
	struct xorg_list list;
	struct smpte2110_20_packet_s *pkt;
};

struct smpte2110_20_receiver_metadata_s
{
	int width;
	int height;
};

static struct smpte2110_20_receiver_element_s *smpte2110_20_receiver_element_alloc()
{
        struct smpte2110_20_receiver_element_s *element = malloc(sizeof(*element));
	return element;
}

static void smpte2110_20_receiver_element_free(struct smpte2110_20_receiver_element_s *element)
{
	if (element->pkt) {
		smpte2110_20_packet_free(element->pkt);
		element->pkt = NULL;
	}
	free(element);
}

struct smpte2110_20_receiver_s *smpte2110_20_receiver_alloc(void *userContext, smpte2110_20_frame_arrival_cb cb)
{
	struct smpte2110_20_receiver_s *ctx = malloc(sizeof(*ctx));

	ctx->userContext = userContext;
	ctx->frameArrivalCallback = cb;
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

static void smpte2110_20_receiver_emit(struct smpte2110_20_receiver_s *ctx, struct smpte2110_20_frame_s *frame)
{
	//smpte2110_20_frame_save(frame);

	/* let the callback take care of frame lifespan, if available. */
	if (ctx->frameArrivalCallback) {
		ctx->frameArrivalCallback(ctx->userContext, frame);
	} else {
		/* No callback, don't leak. */
		smpte2110_20_frame_free(frame);
	}
}

/* Assess and validate the context, glean metadata, make some determinations
 * about expected frame width, height, etc.
 *
 * This is called exlusively from smpte2110_20_receiver_generate()
 * prior to frame creation and re-assembly of the final video frame.
 *
 */
static int smpte2110_20_receiver_generate_metadata(struct smpte2110_20_receiver_s *ctx,
	struct smpte2110_20_receiver_metadata_s *md)
{
	/* TODO: How expensive is this, do we do this on every frame? */
	md->width = 0;
	md->height = 0;

	/* Determine the width and height, accepting the fact that packet loss
	 * could mean we're missing packets. Use the context of "Broadcast Television"
	 * if in doubt, rather than any arbitrary WxH oddball calculation.
	 */

	/* Theory is, the first 20-30 lines should give us enough sense of the line width */
	/* Theory is, the last 20-30 lines should give us enough send of the height */

	return 0;
}

/* For the given receive context, generate a full video frame, dispatch it.  */
static int smpte2110_20_receiver_generate(struct smpte2110_20_receiver_s *ctx)
{
	/* It's important o understand that due to packet loss we may be missing
	 * none or more pixels for this video frame.
	 * Assemble what we can, leave any missing pixels 'missing' in the output frame,
	 * ship the frame anyway, the caller can choose to process appropriately.
	 */

	/* The listElements is always appended to, the spec says that lines
	 * are transmitted starting from pixel line zero and incrementing
	 * to N.
	 */
	if (xorg_list_is_empty(&ctx->listElements))
		return -1;

	struct smpte2110_20_receiver_metadata_s md;
	int ret = smpte2110_20_receiver_generate_metadata(ctx, &md);

	if (ctx->verbose) {
		printf("%s() ", __func__);
		printf("Frame %" PRIi64 " contains the following packets:\n", ctx->videoFramesProcessed);
	}

	/* TODO: hardcoded 720p here. THis width/height/metadata needs to come from somewhere. */

	/* Allocate a frame with a unique number, visible width, visible height, colorspace and
	 * line length stride (in bytes).
	 */
	struct smpte2110_20_frame_s *frame = smpte2110_20_frame_alloc(ctx->videoFramesProcessed, 1280, 720, 2, 3200);

	/* Intensionally, we don't modify the list. A call to reset later will
	 * take care of object lifespan. */

	int entries = 0;
	struct smpte2110_20_receiver_element_s *e;
	xorg_list_for_each_entry(e, &ctx->listElements, list) {
		if (ctx->verbose)
			smpte2110_20_packet_dump(e->pkt);
		smpte2110_20_frame_packet_write(frame, e->pkt);
		entries++;
	}

	if (ctx->verbose) {
		printf("Frame %" PRIi64 " processed %d packets\n", ctx->videoFramesProcessed, entries);
	}

	smpte2110_20_receiver_emit(ctx, frame);

	ctx->videoFramesProcessed++;

	return 0;
}

static void smpte2110_20_receiver_reset(struct smpte2110_20_receiver_s *ctx)
{
	while (!xorg_list_is_empty(&ctx->listElements)) {
		struct smpte2110_20_receiver_element_s *element =
			xorg_list_first_entry(&ctx->listElements, struct smpte2110_20_receiver_element_s, list);

		xorg_list_del(&element->list);
		smpte2110_20_receiver_element_free(element);
	}
}

int smpte2110_20_receiver_write(struct smpte2110_20_receiver_s *ctx, const struct rtp_hdr *rtphdr,
	const unsigned char *buf, int lengthBytes)
{
	if (ctx->appending == 0 && rtphdr->m == 0) {
		/* We're not appending, discard this frame. Waiting for the start of a new frame. */
		return 0;
	}
	if (ctx->appending == 0 && rtphdr->m == 1) {
		ctx->appending = 1;
		ctx->startOfFrame = 1;
		if (ctx->verbose > 0) {
			printf("%s() APPENDING AND START_OF_FRAME BEGINS\n", __func__);
		}
		return 0; 
	}

	if (ctx->startOfFrame) {
		ctx->startOfFrame = 0;
		ctx->rtphdrFirst = *rtphdr;
	}

	ctx->rtphdrCurrent = *rtphdr;

	struct smpte2110_20_receiver_element_s *element = smpte2110_20_receiver_element_alloc();

	smpte2110_20_packet_parse(&element->pkt, ctx->bs, buf, lengthBytes);
	if (!element->pkt) {
		free(element);
		return -1;
	}

	xorg_list_append(&element->list, &ctx->listElements);

	/* We need to determine if this is the last packet for a current frame, and
	 * construct a final video frame and dispatch it accordingly.
	 */
	if (rtphdr->m) {
		/* Last packet in frame. */
		if (smpte2110_20_receiver_generate(ctx) < 0) {
			fprintf(stderr, "Unable to generate a smpte2110_20_receiver video frame, skipping\n");
		}
		smpte2110_20_receiver_reset(ctx);
		ctx->startOfFrame = 1;
//printf("%s() ENTIRE FRAME RECEIVED, PROCESSING\n", __func__);
//exit(0);
	}

	/* Start a brand new receiver, on the beginning of a brand new frame. */

	return 0;
}

