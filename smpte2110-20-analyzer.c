/* Copyright Kernel Labs Inc 2021. All Rights Reserved */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>

#if __linux
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#endif

#include "copyright.h"
#include "smpte2110.h"
#include "klbitstream_readwriter.h"

/* External deps */
#include <smpte2110_sdp_parser.h>
#include <sdp_extractor.h>

struct tool_ctx_s
{
	char filename[256];
	int processed;
	int verbose;
	int SOF;

	struct rtp_hdr_analyzer_s rtpanalyzer;
	struct smpte2110_20_receiver_s *receiver;

	char *sdpfilename;
	unsigned char *sdptxt;
	sdp_extractor_t sdpe;
};

static const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];
	sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);
	return timestamp_string_buf;
}

void *frameArrivalCallback(void *userContext, struct smpte2110_20_frame_s *frame)
{
	smpte2110_20_frame_free(frame);
	return NULL;
}

static void pcap_process_packet(struct tool_ctx_s *ctx, const struct pcap_pkthdr *hdr, const unsigned char *pkt)
{
	const struct ether_header *eth = (struct ether_header *)((unsigned char *)pkt);
	const struct iphdr *ip = (struct iphdr *)((unsigned char *)pkt + sizeof(*eth));
	const struct udphdr *udp = (struct udphdr *)((unsigned char *)ip + sizeof(*ip));
	const struct rtp_hdr *rtphdr = (struct rtp_hdr *)((unsigned char *)udp + sizeof(*udp));
	int i;

	ctx->processed++;
	if (ctx->verbose) {
		printf("pkt %08d\n", ctx->processed);
		printf("    caplen   %4d\n", hdr->caplen);
	}

	if (hdr->caplen < sizeof(*eth) + sizeof(*ip) + sizeof(*udp)) {
		return; /* Discard */
	}

	if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
		return; /* Discard */
	}

	if (ip->protocol != IPPROTO_UDP) {
		return; /* Discard */
	}

	unsigned char *data = (unsigned char *)udp + sizeof(*udp);
	unsigned char *rtpdata = (unsigned char *)udp + sizeof(*udp) + sizeof(*rtphdr);
	int udpdatalen = ntohs(udp->uh_ulen);

	if (ctx->verbose) {
		printf("    payloadlen %d\n", udpdatalen);
	}

	if (ctx->verbose > 1) {
		char s[64], d[64];
		struct in_addr in;
		in.s_addr = ip->saddr;
		sprintf(s, "%s:%d", inet_ntoa(in), ntohs(udp->uh_sport));
		in.s_addr = ip->daddr;
		sprintf(d, "%s:%d", inet_ntoa(in), ntohs(udp->uh_dport));

		printf("        %s %s -> %s (%d) :", timestamp_string(hdr->ts), s, d, udpdatalen);

		if (ctx->verbose > 2) {
			for (i = 0; i < udpdatalen; i++) {
				printf(" %02x", *(data + i));
			}
		} else {
			for (i = 0; i < 16; i++) {
				printf(" %02x", *(data + i));
			}
		}
		printf("\n");
	}

	/* Update the RTP analyzer stats */
	rtp_hdr_write(&ctx->rtpanalyzer, rtphdr);

	if (ctx->SOF) {
		if (ctx->verbose > 1) {
			printf("IS SOF\n");
		}
	}

	if (rtphdr->x) {
		printf("header extensions, abort.\n");
		exit(1);
	}

	int rtpdatalen = udpdatalen - sizeof(struct rtp_hdr);
	if (ctx->verbose > 0) {
		printf("        RTP data length = %d\n", rtpdatalen);
	}

	if (ctx->verbose > 1) {
		printf("            version: %d\n", rtphdr->version);
		printf("            marker: %d\n", rtphdr->m);
		printf("            payload type: %d\n", rtphdr->pt);
		printf("            sequence number: %d\n", ntohs(rtphdr->seq));
		printf("            timestamp: %u / %08x\n", ntohl(rtphdr->ts), ntohl(rtphdr->ts));
	}

	smpte2110_20_receiver_write(ctx->receiver, rtphdr, (const unsigned char *)rtpdata, rtpdatalen);

	if (ctx->verbose > 1) {
		printf("                rtpdata: ");
		for (i = 0; i < rtpdatalen; i++) {
			printf(" %02x", *(data + sizeof(*rtphdr) + i));
		}
		printf("\n");
	}

	if (rtphdr->m) {
		if (ctx->verbose) {
			printf("    SOF indicated\n");
		}
		ctx->SOF = 1;
	}

	if (ctx->SOF == 0)
		return;
}

/* SDP parser doesn't like blank lines, remove them. */
static void cleanupSDP(unsigned char *str)
{
	int trimmed = 0;
	int l = strlen((char *)str);

	for (int i = l - 1; i > 0; i--) {
		if (str[i] == '\n' && str[i - 1] == '\n') {
			memcpy(&str[i - 1], &str[i], l - 1 - i);
			trimmed++;
			str[ l - trimmed] = 0;
		}
	}
	
	// printf("sdp: [%s]\n", str);
}

static void usage()
{
	printf("%s\n", COPYRIGHT);
	printf("Version: %s\n", GIT_VERSION);
	printf("Read a PCAP file, extract SMPTE2110-20 (video) packets and display packet contents.\n\n");

	printf(" -h show command line help\n");
	printf(" -s input.sdp\n");
	printf(" -i <inputfile.pcap>\n");
	printf(" -v increase level of verbosity\n");
	printf(" -a address:port Eg. a.b.c.d:4010 --- TODO\n");
	printf(" -v increase level of verbosity\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		usage();
		exit(1);
	}

	struct tool_ctx_s *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Unable to alloc process context, aborting.\n");
		exit(1);
	}

	int opt;
	while ((opt = getopt(argc, argv, "hi:vs:")) != -1) {
		switch(opt) {
		case 'i':
			strcpy(ctx->filename, optarg);
			break;
		case 'h':
		default:
			usage();
			exit(1);
		case 'v':
			ctx->verbose++;
			break;
		case 's':
			ctx->sdpfilename = strdup(optarg);
			break;
		}
	}

	if (ctx->filename[0] == 0) {
		usage();
		fprintf(stderr, "-i is mandatory, aborting\n");
		exit(1);
	}

	if (ctx->sdpfilename == 0) {
		usage();
		fprintf(stderr, "-s is mandatory, aborting\n");
		exit(1);
	}

	/* Load and Extract SDP details */
	FILE *fh = fopen(ctx->sdpfilename, "rb");
	if (!fh) {
		fprintf(stderr, "Unable to load the %s file, aborting\n", ctx->sdpfilename);
		exit(1);
	}
	fseek(fh, 0, SEEK_END);
	int sdplen = ftell(fh);
	fseek(fh, 0, SEEK_SET);
	ctx->sdptxt = malloc(sdplen);
	int rlen = fread(ctx->sdptxt, 1, sdplen, fh);
	fclose(fh);

	if (rlen <= 0) {
		fprintf(stderr, "Error reading SDP, aborting.\n");
		free(ctx->sdpfilename);
		free(ctx->sdptxt);
		free(ctx);
		exit(1);
	}

	/* SDP parse doesn't like empty lines, remove them. */
	cleanupSDP(ctx->sdptxt);

	ctx->sdpe = sdp_extractor_init(ctx->sdptxt, SDP_STREAM_TYPE_CHAR);
	if (!ctx->sdpe) {
		printf("Illegal content in SDP file, parse failed, aborting.\n");
		printf("RFC4566 is strict, remove any blank lines in your SDP, for example.\n");
		free(ctx->sdpfilename);
		free(ctx->sdptxt);
		free(ctx);
		exit(1);
	}
	printf("SDP Session name: %s\n", sdp_extractor_get_session_name(ctx->sdpe));
	for (int i = 0; i < sdp_extractor_get_stream_num(ctx->sdpe); i++) {
		enum sdp_extractor_spec_sub_type sub_type = sdp_extractor_stream_sub_type(ctx->sdpe, i);

		printf("stream %d\n", i);
		printf("\t%s:%d -- ",
			sdp_extractor_get_dst_ip_by_stream(ctx->sdpe, i),
			sdp_extractor_get_dst_port_by_stream(ctx->sdpe, i)
			);
// MMM
		if (sub_type == SPEC_SUBTYPE_SMPTE_ST2110_20) {
			int colorimetry = sdp_extractor_get_2110_20_colorimetry_by_stream(ctx->sdpe, i);
			int width = sdp_extractor_get_2110_20_width_by_stream(ctx->sdpe, i);
			int height = sdp_extractor_get_2110_20_height_by_stream(ctx->sdpe, i);
			int sampling = sdp_extractor_get_2110_20_sampling_by_stream(ctx->sdpe, i);
			int scans = sdp_extractor_get_2110_20_signal_by_stream(ctx->sdpe, i);
			int depth = sdp_extractor_get_2110_20_depth_by_stream(ctx->sdpe, i);
			printf("\t%dx%d col:%d scans:%d sampling:%d depth:%d", width, height, colorimetry, scans, sampling, depth);
		}

		printf("\n");

	}

#if 0
	// deliberate segfault
	unsigned char *x = NULL;
	*x = 0;
#endif

	/* Allocate some frameworks. */
	ctx->receiver = smpte2110_20_receiver_alloc(ctx, (smpte2110_20_frame_arrival_cb)frameArrivalCallback);
	if (!ctx) {
		fprintf(stderr, "Unable to alloc smpte2110_20 receiver context, aborting.\n");
		free(ctx);
		exit(1);
	}

	/* Reset RTP state tracking. */
	rtp_analyzer_init(&ctx->rtpanalyzer);

	/* Configure tool context. */
	//strcpy(ctx->filename, "../ST2110_pcap_zoo/ST2110-40_ancillary_data.pcap");
	//strcpy(ctx->filename, "../ST2110_pcap_zoo/ST2110-40-Closed_Captions.cap");

	char err[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_offline(ctx->filename, err);
	if (pcap == NULL) {
		fprintf(stderr, "Error reading pcap file: %s, aborting\n", err);
		smpte2110_20_receiver_free(ctx->receiver);
		exit(1);
	}

	struct pcap_pkthdr header;
	const unsigned char *packet = pcap_next(pcap, &header);
	while (packet != NULL) {
		pcap_process_packet(ctx, &header, packet);
		packet = pcap_next(pcap, &header);
	}

	/* Teardown */
	pcap_close(pcap);
	smpte2110_20_receiver_free(ctx->receiver);
	rtp_analyzer_report(&ctx->rtpanalyzer);

	free(ctx->sdptxt);
	sdp_extractor_uninit(ctx->sdpe);
	free(ctx->sdpfilename);
	free(ctx);

	return 0;
}
