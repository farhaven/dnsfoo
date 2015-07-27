#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/queue.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "handlers.h"

/* XXX: un-global these */
struct msghdr rtadv_msghdr;
struct sockaddr_in6 rtadv_from;
char rtadv_answer[1500];
struct iovec rtadv_rcviov;
int rtadv_ifindex;

#define ALLROUTERS "ff02::2"
int
rtadv_setup_handler(const char *dev) {
	struct sockaddr_in6 sin6_allr;
	struct icmp6_filter filt;
	int msglen, sock, flag = 1;
	char *rcvbuf;

	msglen = CMSG_SPACE(sizeof(struct in6_pktinfo) + CMSG_SPACE(sizeof(int)));

	rcvbuf = calloc(1, msglen);
	if (rcvbuf == NULL) {
		err(1, "calloc");
	}

	memset(&sin6_allr, 0, sizeof(sin6_allr));
	sin6_allr.sin6_family = AF_INET6;
	sin6_allr.sin6_len = sizeof(sin6_allr);

	if (inet_pton(AF_INET6, ALLROUTERS, &sin6_allr.sin6_addr.s6_addr) != 1) {
		err(1, "inet_pton");
	}

	if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		err(1, "socket");
	}

	/* XXX: set routing table? */

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &flag, sizeof(flag)) < 0) {
		err(1, "setsockopt IPV6_RECVPKTINFO");
	}

	flag = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &flag, sizeof(flag)) < 0) {
		err(1, "setsockopt IPV6_RECVHOPLIMIT");
	}

	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) < 0) {
		err(1, "setsockopt ICMP6_FILTER");
	}

	rtadv_rcviov.iov_base = (caddr_t)rtadv_answer;
	rtadv_rcviov.iov_len = sizeof(rtadv_answer);
	rtadv_msghdr.msg_name = (caddr_t)&rtadv_from;
	rtadv_msghdr.msg_namelen = sizeof(rtadv_from);
	rtadv_msghdr.msg_iov = &rtadv_rcviov;
	rtadv_msghdr.msg_iovlen = 1;
	rtadv_msghdr.msg_control = (caddr_t) rcvbuf;
	rtadv_msghdr.msg_controllen = msglen;

	rtadv_ifindex = if_nametoindex(dev);
	if (rtadv_ifindex == 0) {
		err(1, "interface %s does not exist", dev);
	}

	return sock;
}

const char* ra_names[] = {
	[ND_OPT_SOURCE_LINKADDR] = "source linkaddr",
	[ND_OPT_TARGET_LINKADDR] = "target linkaddr",
	[ND_OPT_PREFIX_INFORMATION] = "prefix info",
	[ND_OPT_REDIRECTED_HEADER] = "redirected header",
	[ND_OPT_MTU] = "mtu",
	[ND_OPT_ROUTE_INFO] = "route info",
	[ND_OPT_RDNSS] = "rdnss",
	[ND_OPT_DNSSL] = "dnssl"
};

void
rtadv_handle_individual_ra(char *data, ssize_t len, int msgfd) {
	struct nd_router_advert *ra = (struct nd_router_advert*) data;
	struct nd_opt_hdr *opthdr;
	char ntopbuf[INET6_ADDRSTRLEN];
	off_t pkt_off = sizeof(struct nd_router_advert);

	fprintf(stderr, "rtadv: from %s\n", inet_ntop(AF_INET6, &rtadv_from.sin6_addr, ntopbuf, INET6_ADDRSTRLEN));
	fprintf(stderr, "\treachable=%d, retransmit=%d, flags=%x\n",
			ra->nd_ra_reachable,
			ra->nd_ra_retransmit,
			ra->nd_ra_flags_reserved);

	for (pkt_off = sizeof(struct nd_router_advert); pkt_off < len; pkt_off += opthdr->nd_opt_len * 8) {
		opthdr = (struct nd_opt_hdr*)(data + pkt_off);

		fprintf(stderr, "\toff=%lld, type=%02x ", pkt_off, opthdr->nd_opt_type);
		if ((opthdr->nd_opt_type <= ND_OPT_DNSSL) && (ra_names[opthdr->nd_opt_type] != NULL))
			fprintf(stderr, "(%s)\n", ra_names[opthdr->nd_opt_type]);
		else
			fprintf(stderr, "(unknown: %d)\n", opthdr->nd_opt_type);

		if (opthdr->nd_opt_type == ND_OPT_RDNSS) {
			fprintf(stderr, "Would try to parse RDNSS header now.\n");
		}

		if (opthdr->nd_opt_len == 0)
			break;
	}
}

void
rtadv_handle_update(int fd, int msgfd) {
	/* https://tools.ietf.org/html/rfc6106 */
	char ifnamebuf[IFNAMSIZ];
	char ntopbuf[INET6_ADDRSTRLEN];
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	struct icmp6_hdr *icp;
	ssize_t len;
	int ifindex = 0;
	int *hlimp = NULL;

	if ((len = recvmsg(fd, &rtadv_msghdr, MSG_WAITALL)) < 0) {
		warn("recvmsg");
		return;
	}

	if (rtadv_msghdr.msg_iovlen != 1) {
		warn("unexpected number of I/O vectors: %d\n", rtadv_msghdr.msg_iovlen);
		return;
	}

	for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&rtadv_msghdr); cm;
	     cm = (struct cmsghdr *) CMSG_NXTHDR(&rtadv_msghdr, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *) CMSG_DATA(cm);
			ifindex = pi->ipi6_ifindex;
		}

		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_HOPLIMIT &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int))) {
			hlimp = (int*) CMSG_DATA(cm);
		}
	}

	if (ifindex == 0) {
		warn("can't get interface index");
		return;
	}

	if (ifindex != rtadv_ifindex) {
		return;
	}

	if (hlimp == NULL) {
		warn("can't get receiving hop limit");
		return;
	}

	if (len < sizeof(struct nd_router_advert)) {
		warn("short packet");
		return;
	}

	icp = (struct icmp6_hdr*) rtadv_msghdr.msg_iov[0].iov_base;

	if (icp->icmp6_type != ND_ROUTER_ADVERT) {
		warn("received a packet that is not a router advertisement");
		return;
	}

	if (icp->icmp6_code != 0) {
		warn("invalid ICMP6 code %d", icp->icmp6_code);
		return;
	}

	if (*hlimp != 255) {
		warn("invalid RA with hop limit %d received on %s",
		     *hlimp, if_indextoname(ifindex, ifnamebuf));
		return;
	}

	if (pi && !IN6_IS_ADDR_LINKLOCAL(&rtadv_from.sin6_addr)) {
		warn("RA with non link-local source %s received on %s",
		     inet_ntop(AF_INET6, &rtadv_from.sin6_addr, ntopbuf, INET6_ADDRSTRLEN),
		     if_indextoname(ifindex, ifnamebuf));
		return;
	}

	rtadv_handle_individual_ra(rtadv_msghdr.msg_iov[0].iov_base, len, msgfd);
	fprintf(stderr, "\n");
}
