#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/queue.h>
#include <imsg.h>

#include <sys/tame.h>

#include "unbound_update.h"

void
dhcpv4_handle_update(int fd, int msg_fd, void *udata) {
	const char *match = "option domain-name-servers";
	struct imsgbuf ibuf;
	char *buf, *data;
	FILE *f;
	size_t len;

	tame(TAME_MALLOC | TAME_RPATH);

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
	data = calloc(1, strlen(buf) + 1);
	if (data == NULL) {
		err(1, "calloc");
	}
	(void)strlcpy(data, buf, strlen(buf) + 1);

	imsg_init(&ibuf, msg_fd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, data,
	                 strlen(data) + 1) < 0)
		err(1, "imsg_compose");
	free(data);

	do {
		if (msgbuf_write(&ibuf.w) > 0) {
			return;
		}
	} while (errno == EAGAIN);
	err(1, "msgbuf_write");
}
