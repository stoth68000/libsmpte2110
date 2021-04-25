
#include <inttypes.h> 

//
// please define based on your architecture.
// RTP_LITTLE_ENDIAN seems to work for OS X El Capitan
//
#define RTP_LITTLE_ENDIAN 1
struct rtp_hdr {
#if RTP_BIG_ENDIAN
    unsigned int version:2;   /* protocol version */
    unsigned int p:1;         /* padding flag */
    unsigned int x:1;         /* header extension flag */
    unsigned int cc:4;        /* CSRC count */
    unsigned int m:1;         /* marker bit */
    unsigned int pt:7;        /* payload type */
#elif RTP_LITTLE_ENDIAN
    unsigned int cc:4;        /* CSRC count */
    unsigned int x:1;         /* header extension flag */
    unsigned int p:1;         /* padding flag */
    unsigned int version:2;   /* protocol version */
    unsigned int pt:7;        /* payload type */
    unsigned int m:1;         /* marker bit */
#else
#error Define one of RTP_LITTLE_ENDIAN or RTP_BIG_ENDIAN
#endif

    unsigned int seq:16;      /* sequence number */
    u_int32_t ts;               /* timestamp */
    u_int32_t ssrc;             /* synchronization source */
} __attribute__((packed));

struct rtp_hdr_analyzer_s
{
	struct rtp_hdr last;
	int64_t totalPackets;
	int64_t discontinuityEvents;
	int64_t illegalPayloadTypeEvents;
	int64_t illegalTimestampMovementEvents;
	int64_t illegalTimestampStallEvents;

	/* SMPTE2110-20 (Video) Specific */
};

static __inline__ void rtp_analyzer_init(struct rtp_hdr_analyzer_s *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

static __inline__ int rtp_hdr_is_payload_type_valid(const struct rtp_hdr *hdr)
{
	/* SMPTE 2110-10: "All RTP streams shall use dynamic payload types chosen in the
	 * range of 96 through 127, signaled as specified in section 6 of IETF RFC 4566,
	 * unless a fixed payload type designation exists for that RTP stream within the
	 * IETF standard which specifies it."
	*/
	if (hdr->pt < 96 || hdr->pt > 127)
		return 0;

	return 1;
}

static __inline__ int rtp_hdr_is_continious(struct rtp_hdr_analyzer_s *ctx, const struct rtp_hdr *new)
{
	int match = 1;

	if (ctx->last.seq > 0) {
		int next = (ntohs(ctx->last.seq) + 1) % 65536;
		if (next != ntohs(new->seq)) {
			match = 0;
		}
	}

	ctx->last = *new;

	return match;
}

static __inline__ int rtp_hdr_write(struct rtp_hdr_analyzer_s *ctx, const struct rtp_hdr *src)
{
	ctx->totalPackets++;

	/* If the timestamp has moved between frames, but the last frame
	 * didn't have the M bit set (end of frame), the timestamp moved illegally.
	 */
	if (ctx->last.ts && (ctx->last.ts != src->ts) && ctx->last.m == 0) {
		ctx->illegalTimestampMovementEvents++;
	}

	/* If the timestamp NOT moved between frames, and the last frame
	 * had the M bit set (end of frame), the timestamp stalled illegally.
	 */
	if (ctx->last.ts && (ctx->last.ts == src->ts) && ctx->last.m == 1) {
		ctx->illegalTimestampStallEvents++;
	}

	if (rtp_hdr_is_continious(ctx, src) == 0)
		ctx->discontinuityEvents++;

	if (rtp_hdr_is_payload_type_valid(src) == 0)
		ctx->illegalPayloadTypeEvents++;

	return 0;
}

static __inline__ void rtp_analyzer_report(struct rtp_hdr_analyzer_s *ctx)
{
	printf("RTP Analyzer Report:\n");
	printf("\tTotal packets = %" PRIi64 "\n", ctx->totalPackets);
	printf("\tDiscontinuity events = %" PRIi64 "\n", ctx->discontinuityEvents);
	printf("\tIllegal Payload Type events = %" PRIi64 "\n", ctx->illegalPayloadTypeEvents);
	printf("\tIllegal Timestamp Movement events = %" PRIi64 "\n", ctx->illegalTimestampMovementEvents);
	printf("\tIllegal Timestamp Stall events = %" PRIi64 "\n", ctx->illegalTimestampStallEvents);
}

