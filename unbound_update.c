#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/event.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <imsg.h>

#include "unbound_update.h"

#define MAX_NAME_SERVERS 5

void
unbound_update_dispatch(struct unbound_update_msg *msg) {
	char *params[MAX_NAME_SERVERS + 3]; /* unbound-control, forward, final NULL */
	char *p, **srv;
	int numns = 0;
	pid_t child;

	memset(params, 0, sizeof (params));
	params[0] = "unbound-control";
	params[1] = "forward";
	srv = &params[2];
	p = msg->ns;
	while ((numns < MAX_NAME_SERVERS) && (msg->nslen > 0)) {
		if ((asprintf(&srv[numns++], "%s", p)) == -1)
			err(1, "asprintf");
		msg->nslen -= strlen(p) + 1;
		p += strlen(p) + 1;
	}

	switch ((child = fork())) {
		case -1:
			err(1, "fork");
			break;
		case 0:
			fclose(stdout); /* Prevent noise from unbound-control */
			execvp("unbound-control", params);
			err(1, "execvp");
			break;
		default:
			if (waitpid(child, NULL, 0) < 0)
				err(1, "waitpid");
	}

	for (numns = 0; numns < MAX_NAME_SERVERS; numns++) {
		if (!srv[numns])
			break;
		free(srv[numns]);
	}
}

void
unbound_update_handle_imsg(struct imsgbuf *ibuf) {
	struct unbound_update_msg msg;
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

		idata = calloc(1, datalen);
		if (idata == NULL) {
			err(1, "calloc");
		}
		memcpy(idata, imsg.data, datalen);
		idata[datalen - 1] = '\0';
		imsg_free(&imsg);

		if (!unbound_update_msg_unpack(&msg, idata, datalen))
			warnx("failed to unpack update msg");
		free(idata);
#ifndef NDEBUG
		fprintf(stderr, "device=\"%s\"\n", msg.device);
		fprintf(stderr, "nslen =%ld\n", msg.nslen);
#endif
		unbound_update_dispatch(&msg);
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

char *
unbound_update_msg_pack(struct unbound_update_msg *msg, size_t *len) {
	char *p = NULL;

	if ((msg->device == NULL) || (msg->ns == NULL)) {
		warnx("tried to pack an incomplete unbound update msg");
		goto exit_fail;
	}

	if ((p = calloc(1, sizeof(msg->nslen))) == NULL)
		goto exit_fail;
	memcpy(p, &msg->nslen, sizeof(msg->nslen));
	*len = sizeof(msg->nslen);

	if ((p = realloc(p, *len + strlen(msg->device) + 1)) == NULL)
		goto exit_fail;
	(void) strlcpy(p + *len, msg->device, strlen(msg->device) + 1);
	*len += strlen(msg->device) + 1;

	if ((p = realloc(p, *len + msg->nslen)) == NULL)
		goto exit_fail;
	memcpy(p + *len, msg->ns, msg->nslen);
	*len += msg->nslen;

	return p;

exit_fail:
	free(p);
	return NULL;
}

int
unbound_update_msg_unpack(struct unbound_update_msg *msg, char *src, size_t len) {
	size_t off = 0;

	memset(msg, 0x00, sizeof(*msg));

	if (len < sizeof(msg->nslen)) {
		warnx("tried to unpack short update msg (%ld < %ld)", len, sizeof(msg->nslen));
		goto exit_fail;
	}
	memcpy(&msg->nslen, src, sizeof(msg->nslen));
	off += sizeof(msg->nslen);

	if (len - off < strlen(src + off) + 1) {
		warnx("tried to unpack short update msg (%ld < %ld)", len - off, strlen(src + off) + 1);
		goto exit_fail;
	}
	if ((msg->device = calloc(1, strlen(src + off) + 1)) == NULL)
		goto exit_fail;
	(void) strlcpy(msg->device, src + off, strlen(src + off) + 1);
	off += strlen(msg->device) + 1;

	if (len - off < 1) {
		warnx("tried to unpack short update msg (%ld - %ld < 1)", len, off);
		goto exit_fail;
	}

	if ((msg->ns = calloc(1, len - off)) == NULL)
		goto exit_fail;
	memcpy(msg->ns, src + off, len - off);

	return 1;

exit_fail:
	free(msg->device);
	free(msg->ns);
	return 0;
}

int
unbound_update_msg_append_ns(struct unbound_update_msg *msg, const char *ns) {
	msg->ns = realloc(msg->ns, msg->nslen + strlen(ns) + 1);
	if (msg->ns == NULL)
		return 0;
	(void) strlcpy(msg->ns + msg->nslen, ns, strlen(ns) + 1);
	msg->nslen += strlen(ns) + 1;
	return 1;
}
