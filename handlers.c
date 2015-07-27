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
#include <net/if.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <imsg.h>

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

#define BPF_FORMAT "/dev/bpf%d"

int
rtadv_open_bpf(const char *dev) {
	char filename[50];
	struct ifreq ifr;
	int b, sock;

	for (b = 0; ; b++) {
		snprintf(filename, sizeof(filename), BPF_FORMAT, b);
		sock = open(filename, O_RDWR | O_CLOEXEC, 0);
		if (sock >= 0) {
			break;
		}
		if (errno == EBUSY) {
			continue;
		}
		err(1, "Can't find a free BPF");
	}

	(void)strlcpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(sock, BIOCSETIF, &ifr) < 0)
		err(1, "Can't attach interface %s to BPF %s", dev, filename);

	return sock;
}

/* Generated with tcpdump -dd 'icmp6 and ip6[40] == 134' */
struct bpf_insn rtadv_bpf_filter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 5, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 3, 0x0000003a },
	{ 0x30, 0, 0, 0x00000036 },
	{ 0x15, 0, 1, 0x00000086 },
	{ 0x6, 0, 0, 0x00000074 },
	{ 0x6, 0, 0, 0x00000000 },
};

int
rtadv_setup_bpf(const char *dev) {
	struct bpf_version v;
	struct bpf_program p;
	int sock, flag = 1;

	sock = rtadv_open_bpf(dev);

	if (ioctl(sock, BIOCVERSION, &v) < 0)
		err(1, "can't get BPF version");

	if (v.bv_major != BPF_MAJOR_VERSION ||
	    v.bv_minor != BPF_MINOR_VERSION) {
		err(1, "BPF version mismatch");
	}

	if (ioctl(sock, BIOCIMMEDIATE, &flag) < 0) {
		err(1, "can't set immediate flag on BPF socket");
	}

	if (ioctl(sock, BIOCSFILDROP, &flag) < 0) {
		err(1, "can't set filter drop flag on BPF socket");
	}

	p.bf_len = sizeof(rtadv_bpf_filter) / sizeof(rtadv_bpf_filter[0]);
	p.bf_insns = rtadv_bpf_filter;

	if (ioctl(sock, BIOCSETF, &p) < 0) {
		err(1, "can't attach filter to BPF socket");
	}

	return sock;
}

void
rtadv_handle_update(int fd, int msgfd) {
	fprintf(stderr, "packet available on FD %d\n", fd);
}
