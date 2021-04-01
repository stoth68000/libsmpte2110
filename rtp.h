
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

