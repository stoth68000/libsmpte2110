/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

/* An object capable of being handed RTP packets for SMPTE2110-20
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

struct klbs_context_s;
struct smpte2110_20_receiver_s
{
	/* Collection of many smpte2110_20_packet_s packets */
	struct xorg_list listElements;

	struct klbs_context_s *bs;
};

struct smpte2110_20_receiver_s *smpte2110_20_receiver_alloc();
void smpte2110_20_receiver_free(struct smpte2110_20_receiver_s *ctx);
void smpte2110_20_receiver_dump(struct smpte2110_20_receiver_s *ctx);

int smpte2110_20_receiver_write(struct smpte2110_20_receiver_s *ctx, const unsigned char *buf, int lengthBytes);

#endif /* SMPTE2110_20_RECEIVER_H */
