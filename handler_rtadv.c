#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <imsg.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "handlers.h"
#include "unbound_update.h"

#define ALLROUTERS "ff02::2"
#define PKTLEN 1500

struct rtadv_info *
rtadv_setup_handler(const char *dev) {
	/* Inspired by OpenBSD's /usr/src/usr.sbin/rtsol.c */
	struct rtadv_info *rv;
	struct iovec *iovec;
	struct sockaddr_in6 sin6_allr;
	struct icmp6_filter filt;
	int msglen, flag = 1;
	char *rcvbuf;

	rv = calloc(1, sizeof(*rv));
	if (rv == NULL) {
		err(1, "calloc");
	}

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

	if ((rv->sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		err(1, "socket");
	}

	/* XXX: set routing table? */

	if (setsockopt(rv->sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &flag, sizeof(flag)) < 0) {
		err(1, "setsockopt IPV6_RECVPKTINFO");
	}

	flag = 1;
	if (setsockopt(rv->sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &flag, sizeof(flag)) < 0) {
		err(1, "setsockopt IPV6_RECVHOPLIMIT");
	}

	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	if (setsockopt(rv->sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) < 0) {
		err(1, "setsockopt ICMP6_FILTER");
	}

	iovec = calloc(1, sizeof(*iovec));
	if (iovec == NULL)
		err(1, "calloc");
	iovec->iov_base = calloc(1, PKTLEN);
	if (iovec->iov_base == NULL)
		err(1, "calloc");
	iovec->iov_len = PKTLEN;
	rv->msghdr.msg_name = (caddr_t)&rv->from;
	rv->msghdr.msg_namelen = sizeof(rv->from);
	rv->msghdr.msg_iov = iovec;
	rv->msghdr.msg_iovlen = 1;
	rv->msghdr.msg_control = (caddr_t) rcvbuf;
	rv->msghdr.msg_controllen = msglen;

	rv->ifindex = if_nametoindex(dev);
	if (rv->ifindex == 0) {
		err(1, "interface %s does not exist", dev);
	}

	return rv;
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
rtadv_handle_individual_ra(struct rtadv_info *ri, ssize_t len, int msg_fd) {
	/* TODO: don't ignore option life time */
	char *data = ri->msghdr.msg_iov[0].iov_base;
	char *msg = NULL;
	struct imsgbuf ibuf;
	struct nd_opt_hdr *opthdr;
	char ntopbuf[INET6_ADDRSTRLEN];
	off_t pkt_off = sizeof(struct nd_router_advert);

#ifndef NDEBUG
	struct sockaddr_in6 *from = (struct sockaddr_in6*) ri->msghdr.msg_name;

	fprintf(stderr, "rtadv: len: %ld from %s\n",
			len, inet_ntop(AF_INET6, &from->sin6_addr, ntopbuf, INET6_ADDRSTRLEN));
#endif

	for (pkt_off = sizeof(struct nd_router_advert);
	     pkt_off < len; pkt_off += opthdr->nd_opt_len * 8) {
		int optlen;
		char *opt;

		opthdr = (struct nd_opt_hdr*)(data + pkt_off);

		if (opthdr->nd_opt_len == 0)
			break;

		if (opthdr->nd_opt_type != ND_OPT_RDNSS)
			continue;

		optlen = opthdr->nd_opt_len * 8;
#ifndef NDEBUG
		fprintf(stderr, "\t\tRDNSS len=%d hdr=%lu lifetime=%d\n",
				optlen, sizeof(opthdr), ntohl(((struct nd_opt_rdnss*)opthdr)->nd_opt_rdnss_lifetime));
#endif

		optlen -= sizeof(opthdr);
		opt = data + pkt_off + sizeof(opthdr);

		for (; optlen > 0; optlen -= sizeof(struct in6_addr), opt += sizeof(struct in6_addr)) {
			struct in6_addr ns;
			const char* addr;
			memcpy(&ns, opt, sizeof(struct in6_addr));

			addr = inet_ntop(AF_INET6, &ns, ntopbuf, INET6_ADDRSTRLEN);
			if (msg == NULL) {
				msg = calloc(1, strlen(addr) + 1);
				(void)strlcpy(msg, addr, strlen(addr) + 1);
			} else {
				msg = realloc(msg, strlen(msg) + strlen(addr) + 2); /* ',' and terminating '\0' */
				(void)snprintf(msg + strlen(msg), strlen(addr) + 2, ",%s", addr);
			}
		}
	}

	if (msg == NULL)
		return;

	imsg_init(&ibuf, msg_fd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, msg, strlen(msg) + 1) < 0)
		err(1, "imsg_compose");
	free(msg);

	do {
		if (msgbuf_write(&ibuf.w) > 0) {
			return;
		}
	} while (errno == EAGAIN);

	err(1, "msgbuf_write");
}

void
rtadv_handle_update(int fd, int msgfd, void *udata) {
	/* Inspired by OpenBSD's /usr/src/usr.sbin/rtsol.c */
	/* https://tools.ietf.org/html/rfc6106 */
	struct rtadv_info *ri = (struct rtadv_info *) udata;
	char ifnamebuf[IFNAMSIZ];
	char ntopbuf[INET6_ADDRSTRLEN];
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	struct icmp6_hdr *icp;
	ssize_t len;
	int ifindex = 0;
	int *hlimp = NULL;

	setproctitle("router advertisement handler");

	if ((len = recvmsg(fd, &ri->msghdr, MSG_WAITALL)) < 0) {
		warn("recvmsg");
		return;
	}

	if (ri->msghdr.msg_iovlen != 1) {
		warn("unexpected number of I/O vectors: %d\n", ri->msghdr.msg_iovlen);
		return;
	}

	for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&ri->msghdr); cm;
	     cm = (struct cmsghdr *) CMSG_NXTHDR(&ri->msghdr, cm)) {
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

	if (ifindex != ri->ifindex) {
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

	icp = (struct icmp6_hdr*) ri->msghdr.msg_iov[0].iov_base;

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

	if (pi && !IN6_IS_ADDR_LINKLOCAL(&ri->from.sin6_addr)) {
		warn("RA with non link-local source %s received on %s",
		     inet_ntop(AF_INET6, &ri->from.sin6_addr, ntopbuf, INET6_ADDRSTRLEN),
		     if_indextoname(ifindex, ifnamebuf));
		return;
	}

	rtadv_handle_individual_ra(ri, len, msgfd);
}
