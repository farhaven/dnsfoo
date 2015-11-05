#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	size_t nslen;
	time_t expiry;
	char *ns;
};

struct srv_device {
	TAILQ_ENTRY(srv_device) entry;
	TAILQ_HEAD(, srv_source) sources;
	char *name;
};

struct srv_devlist {
	TAILQ_HEAD(, srv_device) devices;
	time_t expiry;
};

void
serverrepo_update_unbound(int msgfd, struct srv_devlist *devices) {
	struct srv_device *dev;
	struct unbound_update_msg msg;
	struct imsgbuf ibuf;
	char *msgdata;
	size_t msglen;

	memset(&msg, 0x00, sizeof(msg));
	msg.type = SRC_UNKNOWN;
	msg.device = strdup("unknown");

	TAILQ_FOREACH(dev, &devices->devices, entry) {
		struct srv_source *src;
		TAILQ_FOREACH(src, &dev->sources, entry) {
			if ((msg.ns = realloc(msg.ns, msg.nslen + src->nslen)) == NULL)
				err(1, "realloc");
			memcpy(msg.ns + msg.nslen, src->ns, src->nslen);
			msg.nslen += src->nslen;
		}
	}

	if ((msgdata = unbound_update_msg_pack(&msg, &msglen)) == NULL)
		err(1, "failed to pack unbound update message");

	imsg_init(&ibuf, msgfd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, msgdata, msglen) < 0)
		err(1, "imsg_compose");
	free(msgdata);

	fprintf(stderr, "%llu: dispatching unbound update msg, dev=%s, nslen=%ld, type=%d\n",
	        time(NULL), msg.device, msg.nslen, msg.type);
	unbound_update_msg_cleanup(&msg);

	do {
		if (msgbuf_write(&ibuf.w) > 0)
			return;
	} while (errno == EAGAIN);

	err(1, "msgbuf_write");
}

void
serverrepo_handle_msg(struct unbound_update_msg *msg, int msgfd, struct srv_devlist *devices) {
	struct srv_device *dev;
	struct srv_source *src;

	TAILQ_FOREACH(dev, &devices->devices, entry) {
		if (!strcmp(dev->name, msg->device))
			break;
	}
	if (dev == NULL) {
		if ((dev = calloc(1, sizeof(struct srv_device))) == NULL)
			err(1, "calloc");
		dev->name = strdup(msg->device);
		TAILQ_INIT(&dev->sources);
		TAILQ_INSERT_TAIL(&devices->devices, dev, entry);
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
	if (msg->lifetime == ~0)
		src->expiry = (time_t) -1;
	else
		src->expiry = time(NULL) + msg->lifetime;
	if ((src->ns = calloc(1, msg->nslen)) == NULL)
		err(1, "calloc");
	memcpy(src->ns, msg->ns, msg->nslen);
	TAILQ_INSERT_TAIL(&dev->sources, src, entry);

	fprintf(stderr, "%llu: new expiry: %lld (%d)\n",
	        time(NULL), src->expiry, src->expiry == (time_t) -1);

	if ((src->expiry != (time_t) -1) &&
	    ((devices->expiry == (time_t) -1) ||
	     (devices->expiry > src->expiry))) {
		devices->expiry = src->expiry;
		fprintf(stderr, "%llu: new expiry: %lld seconds\n", time(NULL), devices->expiry);
	}

	fprintf(stderr, "%llu: dev=%p src=%p\n", time(NULL), (void*) dev, (void*) src);

	serverrepo_update_unbound(msgfd, devices);
}

void
serverrepo_handle_timeout(int msg_fd, struct srv_devlist *devs) {
	struct srv_device *dev = NULL;
	struct srv_source *src = NULL;
	time_t now = time(NULL);

	fprintf(stderr, "%llu: Handling timeout\n", time(NULL));

	for (;;) {
		TAILQ_FOREACH(dev, &devs->devices, entry) {
			TAILQ_FOREACH(src, &dev->sources, entry) {
				if (src->expiry <= now)
					break;
			}
			if (src != NULL)
				break;
		}
		if (src == NULL)
			break;
		fprintf(stderr, "%llu: expired entry: %p, expiry=%lld\n",
		        time(NULL), (void*) src, src->expiry);
		TAILQ_REMOVE(&dev->sources, src, entry);
		free(src->ns);
		free(src);
	}

	/* Update next expiry */
	devs->expiry = (time_t) -1;
	TAILQ_FOREACH(dev, &devs->devices, entry) {
		fprintf(stderr, "%llu: checking device '%s' %d\n",
		        time(NULL), dev->name, TAILQ_EMPTY(&dev->sources));
		TAILQ_FOREACH(src, &dev->sources, entry) {
			fprintf(stderr, "%llu: src->expiry=%lld, dev->expiry=%lld, %d\n",
			        time(NULL), src->expiry, devs->expiry, src->expiry < devs->expiry);
			if (src->expiry == (time_t) -1)
				continue;

			if ((src->expiry < devs->expiry) || (devs->expiry == (time_t) -1))
				devs->expiry = src->expiry;
		}
	}

	fprintf(stderr, "%llu: done with timeout handling, new expiry=%lld\n",
	        time(NULL), devs->expiry);

	serverrepo_update_unbound(msg_fd, devs);
}

int
serverrepo_loop(int msg_fd_handlers, int msg_fd_unbound, struct config *config) {
	struct srv_devlist devices;
	struct kevent ev;
	struct unbound_update_msg msg;
	struct imsgbuf ibuf;
	struct imsg imsg;
	int kq, ret;
	char *imsgdata;
	ssize_t n, datalen;

	setproctitle("server repository");

	if (!privdrop(config))
		err(1, "privdrop");

	if (pledge("stdio rpath", NULL) < 0)
		err(1, "pledge");

	TAILQ_INIT(&devices.devices);
	devices.expiry = (time_t) -1;
	imsg_init(&ibuf, msg_fd_handlers);

	if ((kq = kqueue()) < 0)
		err(1, "kqueue");

	EV_SET(&ev, msg_fd_handlers, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);

	if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0)
		err(1, "kevent");

	for (;;) {
		if (devices.expiry != (time_t) -1) {
			struct timespec t = {devices.expiry - time(NULL)};
			ret = kevent(kq, NULL, 0, &ev, 1, &t);
		} else
			ret = kevent(kq, NULL, 0, &ev, 1, NULL);

		switch (ret) {
			case 0:
				/* Timeout */
				serverrepo_handle_timeout(msg_fd_unbound, &devices);
				break;
			case -1:
				err(1, "kevent");
				break;
			case 1:
				if ((n = imsg_read(&ibuf)) == -1 || n == 0)
					err(1, "imsg_read");

				while ((n = imsg_get(&ibuf, &imsg) > 0)) {
					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
					fprintf(stderr, "%llu: got %ld bytes of payload\n", time(NULL), datalen);

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
				break;
			default:
				errx(1, "unexpected number of events: %d", ret);
				break;
		}
	}
}
