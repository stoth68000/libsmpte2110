/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

/* An object capable of being handed RTP packets for SMPTE2110-20 (video).
 * Collects network RTP fragments, converts them into smpte2110_20_frame_s
 * objects in a helper role. Provides those smpte2110_20_frame_s objects
 * to higher level applications.
 *
 * This stack is based around specification/date: SMPTE ST 2110-20:2017
 *
 * Network errors, status and generate "spec/transmission" difficulties
 * are consolidated into this single helper layer.
 *
 * Mode of operation:
 * 
 * Take RTP frames via smpte2110_20_receiver_write().
 * Waits for the start of frame marker.
 * Creates an element specific to the rtp frame.
 * Parses the content of the element.
 * Appends the element to a fifo list.
 * Once the last packet for a full video frame is received,
 *  - 
 *
 * How to implement this framework into your application:
 *
 * 1. Allocate a receiver helper with:
 * struct smpte2110_20_receiver_s *ctx = smpte2110_20_receiver_alloc();
 *
 * 2. feed RTP frames into the framewirk with:
 * int smpte2110_20_receiver_write(ctx, const struct rtp_hdr *rtphdr, const uint8_t *buf, int lengthBytes);
 *
 * 3. On process teardown, termination, free the framework:
 * mpte2110_20_receiver_free(ctx);
 *




 * make parses them, makes sense of them, turned them into video frames
 * with correct timing.
 *
 * This object doesn't contain any RTP / UDP receive code, it's handed
 * RTP frames already received from the network.
 */

#ifndef SMPTE2110_20_RECEIVER_H
#define SMPTE2110_20_RECEIVER_H

#include "smpte2110.h"

#include "xorg-list.h"

struct smpte2110_20_frame_s;
typedef void (*smpte2110_20_frame_arrival_cb)(void *userContext, struct smpte2110_20_frame_s *frame);

struct klbs_context_s;
struct smpte2110_20_receiver_s
{
	/* User alloc args */
	void *userContext;
	smpte2110_20_frame_arrival_cb frameArrivalCallback;
	int verbose;

	/* TODO: Mutex on this list to prevent multiple entrants. */
	/* Collection of many smpte2110_20_packet_s packets */
	struct xorg_list listElements;

	struct klbs_context_s *bs;

	struct rtp_hdr rtphdrFirst;
	struct rtp_hdr rtphdrCurrent;

	int appending;
	int startOfFrame;

	int64_t videoFramesProcessed;
};

/* userContext and cb may be NULL, but then the framework operates in a debug dumping mode only. */
struct smpte2110_20_receiver_s *smpte2110_20_receiver_alloc(void *userContext, smpte2110_20_frame_arrival_cb cb);
void smpte2110_20_receiver_free(struct smpte2110_20_receiver_s *ctx);
void smpte2110_20_receiver_dump(struct smpte2110_20_receiver_s *ctx);

int smpte2110_20_receiver_write(struct smpte2110_20_receiver_s *ctx, const struct rtp_hdr *rtphdr, const unsigned char *buf, int lengthBytes);

#endif /* SMPTE2110_20_RECEIVER_H */
