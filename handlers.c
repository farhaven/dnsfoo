#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <imsg.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include "unbound_update.h"

void
dhcpv4_handle_update(int fd, int msg_fd) {
	const char *match = "option domain-name-servers";
	struct imsgbuf ibuf;
	char *buf, *data;
	FILE *f;
	size_t len;

	setproctitle("dhcpv4 lease parser");

	if ((f = fdopen(fd, "r")) == NULL) {
		err(1, "fdopen");
	}
	fseek(f, 0, SEEK_SET);

	/* Skip lines until we found the one we're interested in */
	while ((buf = fgetln(f, &len)) != NULL) {
		if (len <= strlen(match) + 1) {
			continue;
		}

		/* The last char on a line is ';' which we don't need anyway */
		len -= 1;
		buf[len - 1] = '\0';

		if ((buf = strstr(buf, match)) == NULL) {
			continue;
		}

		buf += strlen(match) + 1;

		/* The rest of the file isn't interesting, let's skip it */
		break;
	}

	if (buf == NULL) {
		/* No DNS info found */
		return;
	}

	/* Copy data to a safe space */
	data = calloc(strlen(buf) + 1, sizeof(char));
	if (data == NULL) {
		err(1, "calloc");
	}
	(void)strlcpy(data, buf, strlen(buf) + 1);

	imsg_init(&ibuf, msg_fd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, data, strlen(data) + 1) < 0)
		err(1, "imsg_compose");
	free(data);

	do {
		if (msgbuf_write(&ibuf.w) > 0) {
			return;
		}
	} while (errno == EAGAIN);
	err(1, "msgbuf_write");
}


/* XXX: un-global these */
struct msghdr rtadv_msghdr;
struct sockaddr_in6 rtadv_from;
char rtadv_answer[1500];
struct iovec rtadv_rcviov[2];
int rtadv_ifindex;

#define ALLROUTERS "ff02::2"
int
rtadv_setup_handler(const char *dev) {
	struct sockaddr_in6 sin6_allr;
	struct icmp6_filter filt;
	int msglen, sock, flag = 1;
	char *rcvbuf;

	msglen = CMSG_SPACE(sizeof(struct in6_pktinfo) + CMSG_SPACE(sizeof(int)));

	rcvbuf = malloc(msglen);
	if (rcvbuf == NULL) {
		err(1, "malloc");
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

	rtadv_rcviov[0].iov_base = (caddr_t)rtadv_answer;
	rtadv_rcviov[0].iov_len = sizeof(rtadv_answer);
	rtadv_msghdr.msg_name = (caddr_t)&rtadv_from;
	rtadv_msghdr.msg_namelen = sizeof(rtadv_from);
	rtadv_msghdr.msg_iov = rtadv_rcviov;
	rtadv_msghdr.msg_iovlen = 1;
	rtadv_msghdr.msg_control = (caddr_t) rcvbuf;
	rtadv_msghdr.msg_controllen = msglen;

	rtadv_ifindex = if_nametoindex(dev);
	if (rtadv_ifindex == 0) {
		err(1, "interface %s does not exist", dev);
	}

	return sock;
}

void
rtadv_handle_update(int fd, int msgfd) {
	/* https://tools.ietf.org/html/rfc6106 */
	char ifnamebuf[IFNAMSIZ];
	char ntopbuf[INET6_ADDRSTRLEN];
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	struct icmp6_hdr *icp;
	struct icmp6_nd_router_advert *ra;
	int len, idx, ifindex = 0;
	int *hlimp = NULL;

	if ((len = recvmsg(fd, &rtadv_msghdr, 0)) < 0) {
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

	ra = (struct icmp6_nd_router_advert*) rtadv_msghdr.msg_iov[0].iov_base;

	fprintf(stderr, "rtadv: from=%s\n", inet_ntop(AF_INET6, &rtadv_from.sin6_addr, ntopbuf, INET6_ADDRSTRLEN));
	for (idx = 0; idx < rtadv_msghdr.msg_iovlen; idx++) {
		fprintf(stderr, "\tvec #%d: len=%ld\n", idx, rtadv_msghdr.msg_iov[idx].iov_len);
	}
}
