#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <imsg.h>

#include "unbound_update.h"

void
unbound_update_handle_imsg(struct imsgbuf *ibuf) {
	struct imsg imsg;
	ssize_t n, datalen;
	char *idata;

	if ((n = imsg_read(ibuf)) == -1 || n == 0) {
		err(1, "imsg_read");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			err(1, "imsg_get");
		}
		if (n == 0) /* No more messages */
			return;

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
			case MSG_UNBOUND_UPDATE:
				break;
			default:
				warnx("unknown IMSG received: %d", imsg.hdr.type);
				continue;
		}

		idata = calloc(datalen, sizeof(char));
		if (idata == NULL) {
			err(1, "calloc");
		}
		memcpy(idata, imsg.data, datalen);
		idata[datalen - 1] = '\0';
		fprintf(stderr, "got unbound update data: \"%s\"\n", idata);
		imsg_free(&imsg);
	}
}

int
unbound_update_loop(int msg_fd) {
	struct imsgbuf ibuf;
	struct kevent ev;
	int kq;

	setproctitle("unbound update loop");

	imsg_init(&ibuf, msg_fd);

	if ((kq = kqueue()) < 0) {
		err(1, "kqueue");
	}

	EV_SET(&ev, msg_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);

	if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
		err(1, "kevent");
	}

	for (;;) {
		if (kevent(kq, NULL, 0, &ev, 1, NULL) < 1) {
			err(1, "kevent");
		}
		unbound_update_handle_imsg(&ibuf);
	}

	return 1;
}
