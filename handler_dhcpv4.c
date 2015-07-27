#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
