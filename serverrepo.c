#include <err.h>
#include <errno.h>
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
serverrepo_handle_msg(struct unbound_update_msg *msg, int msgfd) {
	struct imsgbuf ibuf;
	char *msgdata;
	size_t msglen;

	if ((msgdata = unbound_update_msg_pack(msg, &msglen)) == NULL)
		err(1, "failed to pack unbound update message");

	imsg_init(&ibuf, msgfd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, msgdata, msglen) < 0)
		err(1, "imsg_compose");
	free(msgdata);

	fprintf(stderr, "dispatching unbound update msg, dev=%s, nslen=%ld, type=%d\n",
	        msg->device, msg->nslen, msg->type);

	do {
		if (msgbuf_write(&ibuf.w) > 0)
			return;
	} while (errno == EAGAIN);

	err(1, "msgbuf_write");
}

int
serverrepo_loop(int msg_fd_handlers, int msg_fd_unbound) {
	struct kevent ev;
	struct unbound_update_msg msg;
	struct imsgbuf ibuf;
	struct imsg imsg;
	int kq;
	char *imsgdata;
	ssize_t n, datalen;

	setproctitle("conflict resolution");

	imsg_init(&ibuf, msg_fd_handlers);

	if ((kq = kqueue()) < 0)
		err(1, "kqueue");

	EV_SET(&ev, msg_fd_handlers, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);

	if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0)
		err(1, "kevent");

	for (;;) {
		if (kevent(kq, NULL, 0, &ev, 1, NULL) < 1)
			err(1, "kevent");

		fprintf(stderr, "got event on FD %d\n", (int) ev.ident);

		if ((n = imsg_read(&ibuf)) == -1 || n == 0)
			err(1, "imsg_read");

		while ((n = imsg_get(&ibuf, &imsg) > 0)) {
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			fprintf(stderr, "got %ld bytes of payload\n", datalen);

			if (imsg.hdr.type != MSG_UNBOUND_UPDATE)
				errx(1, "unknown IMSG received: %d", imsg.hdr.type);

			if ((imsgdata = calloc(1, datalen)) == NULL)
				err(1, "calloc");
			memcpy(imsgdata, imsg.data, datalen);
			imsgdata[datalen - 1] = '\0';
			imsg_free(&imsg);

			if (!unbound_update_msg_unpack(&msg, imsgdata, datalen))
				err(1, "failed to unpack update msg");
			free(imsgdata);

			serverrepo_handle_msg(&msg, msg_fd_unbound);
			unbound_update_msg_cleanup(&msg);
		}

		if (n == -1)
			err(1, "imsg_get");
	}
}
