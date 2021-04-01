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
#include "rfc8331.h"
#include "rtp.h"
#include "klbitstream_readwriter.h"

struct tool_ctx_s
{
	char filename[256];
	int processed;
	int verbose;
	int SOF;

	struct klbs_context_s *bs;
};

static const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];
	sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);
	return timestamp_string_buf;
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

		for (i = 0; i < udpdatalen; i++) {
			printf(" %02x", *(data + i));
		}
		printf("\n");
	}

	if (ctx->SOF) {
	}

	if (rtphdr->x) {
		printf("header extensions, abort.\n");
		exit(1);
	}

	int rtpdatalen = udpdatalen - sizeof(struct rtp_hdr);
	printf("        RTP data length = %d\n", rtpdatalen);
	printf("            version: %d\n", rtphdr->version);
	printf("            marker: %d\n", rtphdr->m);
	printf("            payload type: %d\n", rtphdr->pt);
	printf("            sequence number: %d\n", ntohs(rtphdr->seq));
	printf("            timestamp: %u / %08x\n", ntohl(rtphdr->ts), ntohl(rtphdr->ts));

	struct rfc8331_s *rfchdr;
	rfc8331_parse(&rfchdr, ctx->bs, (const unsigned char *)rtpdata, rtpdatalen);
	rfc8331_dump(rfchdr);
	rfc8331_free(rfchdr);

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

static void tool_usage()
{
	printf("%s\n", COPYRIGHT);
	printf("Version: %s\n", GIT_VERSION);
	printf("Read a PCAP file, extract SMPTE2110-40 packets and display packet contents.\n\n");

	printf(" -h show command line help\n");
	printf(" -i <inputfile.pcap>\n");
	printf(" -v increase level of verbosity\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = calloc(1, sizeof(*ctx));
	ctx->bs = klbs_alloc();

	if (argc == 1) {
		tool_usage();
		exit(1);
	}

	int opt;
	while ((opt = getopt(argc, argv, "hi:v")) != -1) {
		switch(opt) {
		case 'i':
			strcpy(ctx->filename, optarg);
			break;
		case 'h':
		default:
			tool_usage();
			exit(1);
		case 'v':
			ctx->verbose++;
			break;
		}
	}

	if (ctx->filename[0] == 0) {
		tool_usage();
		exit(1);
	}

	/* Configure tool context. */
	//strcpy(ctx->filename, "../ST2110_pcap_zoo/ST2110-40_ancillary_data.pcap");
	//strcpy(ctx->filename, "../ST2110_pcap_zoo/ST2110-40-Closed_Captions.cap");

	char err[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_offline(ctx->filename, err);
	if (pcap == NULL) {
		fprintf(stderr, "Error reading pcap file: %s, aborting\n", err);
		exit(1);
	}

	struct pcap_pkthdr header;
	const unsigned char *packet = pcap_next(pcap, &header);
	while (packet != NULL) {
		pcap_process_packet(ctx, &header, packet);
		packet = pcap_next(pcap, &header);
	}

	pcap_close(pcap);
	klbs_free(ctx->bs);
	free(ctx);

	return 0;
}
