#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <imsg.h>
#include <kvm.h>

#include "dnsfoo.h"
#include "config.h"
#include "upstream_update.h"

#define MAX_NAME_SERVERS 5

void
upstream_update_dispatch_rebound(struct upstream_update_msg *msg) {
	char errbuf[_POSIX2_LINE_MAX];
	struct kinfo_proc *plist;
	int fd, nprocs, idx;
	kvm_t *kvm;
	pid_t rebound_pid = 0;

	if (msg->nslen <= 0) {
		return;
	}

	/* XXX: detect config file from rebound commandline params? */
	if ((fd = open("/etc/rebound.conf", O_TRUNC | O_WRONLY | O_CREAT, 0644)) < 0) {
		err(1, "open");
	}

	/* Rebound has only one upstream, so we only use the first one from the message */
	fprintf(stderr, "%llu: writing \"%s\" to rebound conf as new name server\n", time(NULL), msg->ns);
	dprintf(fd, "%s\n", msg->ns);
	close(fd);

	/* HUP rebound */
	kvm = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
	if (!kvm) {
		errx(1, "%s", errbuf);
	}
	plist = kvm_getprocs(kvm, KERN_PROC_ALL, 0, sizeof(*plist), &nprocs);
	if (!plist) {
		errx(1, "%s", kvm_geterr(kvm));
	}
	for (idx = 0; idx < nprocs; idx++) {
		if (!strcmp(plist[idx].p_comm, "rebound") && plist[idx].p_uid == 0) {
			rebound_pid = plist[idx].p_pid;
		}
	}
	kvm_close(kvm);

	if (rebound_pid == 0) {
		fprintf(stderr, "%llu: couldn't determine rebound parent PID\n", time(NULL));
		return;
	}

	if (kill(rebound_pid, SIGHUP) == -1) {
		fprintf(stderr, "%llu: signalling rebound (%d): %s\n", time(NULL), rebound_pid, strerror(errno));
	}
}

void
upstream_update_dispatch_unbound(struct upstream_update_msg *msg) {
	char *params[MAX_NAME_SERVERS + 4]; /* unbound-control, forward_{add, remove}, '.', final NULL */
	char *p, **srv;
	int numns = 0;
	pid_t child;

	memset(params, 0, sizeof (params));
	params[0] = "unbound-control";
	params[1] = "forward_remove";
	params[2] = ".";

	if (msg->nslen > 0) {
		size_t nslen = msg->nslen;
		params[1] = "forward_add";
		srv = &params[3];
		p = msg->ns;
		while ((numns < MAX_NAME_SERVERS) && (nslen > 0)) {
			if ((asprintf(&srv[numns++], "%s", p)) == -1)
				err(1, "asprintf");
			nslen -= strlen(p) + 1;
			p += strlen(p) + 1;
		}

		if (nslen > 0) {
			warnx("Ignoring further name servers");
		}
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

	/* Flush out answers from old name servers */
	if (system("unbound-control flush_zone .") < 0) {
		err(1, "system");
	}

	if (msg->nslen <= 0) {
		return;
	}

	for (numns = 0; numns < MAX_NAME_SERVERS; numns++) {
		if (srv[numns] == NULL)
			break;
		free(srv[numns]);
	}
}

void
upstream_update_handle_imsg(struct imsgbuf *ibuf, struct config *config) {
	struct upstream_update_msg msg;
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
			case MSG_UPSTREAM_UPDATE:
				break;
			default:
				warnx("%llu: unknown IMSG received: %d", time(NULL), imsg.hdr.type);
				continue;
		}

		if ((idata = calloc(1, datalen)) == NULL) {
			err(1, "calloc");
		}
		memcpy(idata, imsg.data, datalen);
		idata[datalen - 1] = '\0';
		imsg_free(&imsg);

		if (!upstream_update_msg_unpack(&msg, idata, datalen))
			errx(1, "failed to unpack update msg");
		free(idata);
#ifndef NDEBUG
		fprintf(stderr, "%llu: device=\"%s\", nslen=%ld lifetime=%u\n",
		        time(NULL), msg.device, msg.nslen, msg.lifetime);
#endif
		if (config->srvtype == SRV_UNBOUND) {
			upstream_update_dispatch_unbound(&msg);
		} else {
			upstream_update_dispatch_rebound(&msg);
		}
		upstream_update_msg_cleanup(&msg);
	}
}

int
upstream_update_loop(int msg_fd, struct config *config) {
	struct imsgbuf ibuf;
	struct kevent ev;
	int kq;

	setproctitle("upstream update loop");

	if (config->srvtype != SRV_REBOUND) {
		/* XXX: move signalling in upstream_update_dispatch_rebound to parent */
		if (!privdrop(config))
			err(1, "privdrop");
	}

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
		upstream_update_handle_imsg(&ibuf, config);
	}

	return 1;
}

char *
upstream_update_msg_pack(struct upstream_update_msg *msg, size_t *len) {
	char *p = NULL;

	if (msg->device == NULL) {
		warnx("%llu: tried to pack an incomplete upstream update msg", time(NULL));
		goto exit_fail;
	}

	if ((p = calloc(1, sizeof(msg->type))) == NULL)
		goto exit_fail;
	memcpy(p, &msg->type, sizeof(msg->type));
	*len = sizeof(msg->type);

	if ((p = realloc(p, *len + sizeof(msg->nslen))) == NULL)
		goto exit_fail;
	memcpy(p + *len, &msg->nslen, sizeof(msg->nslen));
	*len += sizeof(msg->nslen);

	if ((p = realloc(p, *len + sizeof(msg->lifetime))) == NULL)
		goto exit_fail;
	memcpy(p + *len, &msg->lifetime, sizeof(msg->lifetime));
	*len += sizeof(msg->lifetime);

	if ((p = realloc(p, *len + strlen(msg->device) + 1)) == NULL)
		goto exit_fail;
	(void) strlcpy(p + *len, msg->device, strlen(msg->device) + 1);
	*len += strlen(msg->device) + 1;

	if (msg->ns != NULL) {
		if ((p = realloc(p, *len + msg->nslen)) == NULL)
			goto exit_fail;
		memcpy(p + *len, msg->ns, msg->nslen);
		*len += msg->nslen;
	}

	return p;

exit_fail:
	free(p);
	return NULL;
}

int
upstream_update_msg_unpack(struct upstream_update_msg *msg, char *src, size_t srclen) {
	size_t off = 0, len;

	memset(msg, 0x00, sizeof(*msg));

	if (srclen < sizeof(msg->type)) {
		warnx("%llu: tried to unpack short update msg (%ld < %ld)",
		      time(NULL), srclen, sizeof(msg->nslen));
		goto exit_fail;
	}
	memcpy(&msg->type, src, sizeof(msg->type));
	off += sizeof(msg->type);

	len = srclen - off;
	if (len < sizeof(msg->nslen)) {
		warnx("%llu: tried to unpack short update msg (%ld < %ld)",
		      time(NULL), len, sizeof(msg->nslen));
		goto exit_fail;
	}
	memcpy(&msg->nslen, src + off, sizeof(msg->nslen));
	off += sizeof(msg->nslen);

	if (srclen - off < sizeof(msg->lifetime)) {
		warnx("%llu: tried to unpack short update msg (%ld < %ld)",
		      time(NULL), srclen - off, sizeof(msg->lifetime));
		goto exit_fail;
	}
	memcpy(&msg->lifetime, src + off, sizeof(msg->lifetime));
	off += sizeof(msg->lifetime);

	len = srclen - off;
	if (len < strnlen(src + off, len) + 1) {
		warnx("%llu: tried to unpack short update msg (%ld < %ld)",
		      time(NULL), len, strnlen(src + off, len) + 1);
		goto exit_fail;
	}
	if ((msg->device = calloc(1, strnlen(src + off, len) + 1)) == NULL)
		goto exit_fail;
	(void) strlcpy(msg->device, src + off, strnlen(src + off, len) + 1);
	off += strlen(msg->device) + 1;

	if (msg->nslen > 0) {
		if (srclen - off < 1) {
			warnx("%llu: tried to unpack short update msg (%ld - %ld < 1), nslen = %ld",
			      time(NULL), srclen, off, msg->nslen);
			goto exit_fail;
		}

		len = srclen - off;
		if ((msg->ns = calloc(1, len)) == NULL)
			goto exit_fail;
		memcpy(msg->ns, src + off, len);
	} else
		msg->ns = NULL;

	return 1;

exit_fail:
	upstream_update_msg_cleanup(msg);
	return 0;
}

int
upstream_update_msg_append_ns(struct upstream_update_msg *msg, const char *ns) {
	msg->ns = realloc(msg->ns, msg->nslen + strlen(ns) + 1);
	if (msg->ns == NULL)
		return 0;
	(void) strlcpy(msg->ns + msg->nslen, ns, strlen(ns) + 1);
	msg->nslen += strlen(ns) + 1;
	return 1;
}

void
upstream_update_msg_cleanup(struct upstream_update_msg *msg) {
	free(msg->device);
	free(msg->ns);
	memset(msg, 0x00, sizeof(*msg));
}
