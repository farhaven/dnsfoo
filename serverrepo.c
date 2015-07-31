#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/tame.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <imsg.h>

#include "dnsfoo.h"
#include "config.h"
#include "unbound_update.h"

struct srv_source {
	TAILQ_ENTRY(srv_source) entry;
	enum srctype type;
	char *ns;
	size_t nslen;
};

struct srv_device {
	TAILQ_ENTRY(srv_device) entry;
	TAILQ_HEAD(, srv_source) sources;
	char *name;
};

typedef TAILQ_HEAD(, srv_device) srv_devlist;

void
serverrepo_set_source(struct unbound_update_msg *msg, srv_devlist *devices) {
	struct srv_device *dev;
	struct srv_source *src;

	TAILQ_FOREACH(dev, devices, entry) {
		if (!strcmp(dev->name, msg->device))
			break;
	}
	if (dev == NULL) {
		if ((dev = calloc(1, sizeof(struct srv_device))) == NULL)
			err(1, "calloc");
		dev->name = strdup(msg->device);
		TAILQ_INIT(&dev->sources);
		TAILQ_INSERT_TAIL(devices, dev, entry);
	}

	TAILQ_FOREACH(src, &dev->sources, entry) {
		if (src->type == msg->type)
			break;
	}
	if (src != NULL) {
		TAILQ_REMOVE(&dev->sources, src, entry);
		free(src->ns);
		free(src);
	}
	if ((src = calloc(1, sizeof(struct srv_source))) == NULL)
		err(1, "calloc");
	src->type = msg->type;
	src->nslen = msg->nslen;
	if ((src->ns = calloc(1, msg->nslen)) == NULL)
		err(1, "calloc");
	memcpy(src->ns, msg->ns, msg->nslen);
	TAILQ_INSERT_TAIL(&dev->sources, src, entry);

	fprintf(stderr, "dev=%p src=%p\n", (void*) dev, (void*) src);
}

void
serverrepo_handle_msg(struct unbound_update_msg *msg_in, int msgfd, srv_devlist *devices) {
	struct unbound_update_msg msg_out;
	struct srv_device *dev;
	struct imsgbuf ibuf;
	char *msgdata;
	size_t msglen;

	serverrepo_set_source(msg_in, devices);

	memset(&msg_out, 0x00, sizeof(msg_out));
	msg_out.type = msg_in->type;
	msg_out.device = strdup(msg_in->device);

	TAILQ_FOREACH(dev, devices, entry) {
		struct srv_source *src;
		if (strcmp(dev->name, msg_in->device))
			continue;
		TAILQ_FOREACH(src, &dev->sources, entry) {
			if ((msg_out.ns = realloc(msg_out.ns, msg_out.nslen + src->nslen)) == NULL)
				err(1, "realloc");
			memcpy(msg_out.ns + msg_out.nslen, src->ns, src->nslen);
			msg_out.nslen += src->nslen;
		}
	}

	if ((msgdata = unbound_update_msg_pack(&msg_out, &msglen)) == NULL)
		err(1, "failed to pack unbound update message");

	imsg_init(&ibuf, msgfd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, msgdata, msglen) < 0)
		err(1, "imsg_compose");
	free(msgdata);

	fprintf(stderr, "dispatching unbound update msg, dev=%s, nslen=%ld, type=%d\n",
	        msg_out.device, msg_out.nslen, msg_out.type);
	unbound_update_msg_cleanup(&msg_out);

	do {
		if (msgbuf_write(&ibuf.w) > 0)
			return;
	} while (errno == EAGAIN);

	err(1, "msgbuf_write");
}

int
serverrepo_loop(int msg_fd_handlers, int msg_fd_unbound, struct config *config) {
	srv_devlist devices;
	struct kevent ev;
	struct unbound_update_msg msg;
	struct imsgbuf ibuf;
	struct imsg imsg;
	int kq;
	char *imsgdata;
	ssize_t n, datalen;

	setproctitle("server repository");

	if (!privdrop(config->user))
		err(1, "privdrop");

	tame(TAME_MALLOC|TAME_RPATH);

	TAILQ_INIT(&devices);
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

			serverrepo_handle_msg(&msg, msg_fd_unbound, &devices);
			unbound_update_msg_cleanup(&msg);
		}

		if (n == -1)
			err(1, "imsg_get");
	}
}
