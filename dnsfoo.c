#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/event.h>

#include "config.h"
#include "handlers.h"
#include "unbound_update.h"

struct fileinfo {
	int fd;
	struct kevent ev;
	void (*handler)(int, int, void*);
};

int
eventloop(struct fileinfo *fi, ssize_t nfi, int msg_fd) {
	struct kevent ev;
	int kq;
	off_t idx;

	setproctitle("event loop");

	if ((kq = kqueue()) < 0) {
		err(1, "kqueue");
	}

	for (idx = 0; idx < nfi; idx++) {
		if (kevent(kq, &fi[idx].ev, 1, NULL, 0, NULL) < 0) {
			err(1, "kevent for FD %d", fi[idx].fd);
		}
	}

	while (1) {
		pid_t child;

		if (kevent(kq, NULL, 0, &ev, 1, NULL) < 1) {
			err(1, "kevent");
		}

		switch ((child = fork())) {
			case 0:
				for (idx = 0; idx < nfi; idx++) {
					if (ev.ident == fi[idx].fd) {
						fi[idx].handler(ev.ident, msg_fd, ev.udata);
						break;
					}
				}
				if (idx == nfi) {
					/* File handle not found */
					err(1, "Got event for unknown file handle %d", (int) ev.ident);
				}
				exit(0);
				break;
			case -1:
				err(1, "fork");
				break;
			default:
				waitpid(child, NULL, 0);
				break;
		}
	}

	return 1;
}

int
main(void) {
	pid_t cpids[2] = { -1, -1 };
	struct rtadv_info *ri;
	struct fileinfo *fi = NULL;
	struct source *sp;
	struct config *config;
	int nchildren = 0, nfi = 0;
	int msg_fds[2];

	setproctitle(NULL);

	config = parse_config("dnsfoo.conf");
	if (config == NULL) {
		errx(1, "Couldn't parse config");
	}
	TAILQ_FOREACH(sp, &config->sources, entry) {
		struct srcspec *src;
#ifndef NDEBUG
		fprintf(stderr, "dev=%s\n", sp->device);
#endif
		TAILQ_FOREACH(src, &sp->specs->l, entry) {
			fi = reallocarray(fi, nfi + 1, sizeof(*fi));
			switch (src->type) {
				case SRC_DHCPV4:
					fi[nfi].handler = dhcpv4_handle_update;
					fi[nfi].fd = open(src->source, O_RDONLY);
					if (fi[nfi].fd < 0) {
						err(1, "open(\"%s\")", src->source);
					}
					EV_SET(&fi[nfi].ev, fi[nfi].fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, NULL);
					break;
				case SRC_RTADV:
					ri = rtadv_setup_handler(sp->device);
					fi[nfi].handler = rtadv_handle_update;
					fi[nfi].fd = ri->sock;
					EV_SET(&fi[nfi].ev, fi[nfi].fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, ri);
					break;
				default:
					errx(1, "unknown source type %d", src->type);
			}
			nfi++;
#ifndef NDEBUG
			printf("\tp=%p t=%d %d\n", (void*) src, src->type, SRC_DHCPV4);
			if (src->type == SRC_DHCPV4)
				printf("\t\tsrc=%s\n", src->source);
#endif
		}
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, msg_fds) == -1) {
		err(1, "socketpair");
	}

	switch ((cpids[0] = fork())) {
		case 0:
			exit(unbound_update_loop(msg_fds[0]));
			break;
		case -1:
			err(1, "fork");
			break;
		default:
#ifndef NDEBUG
			fprintf(stderr, "unbound update loop forked (%d)\n", cpids[0]);
#endif
			close(msg_fds[0]);
			nchildren++;
			break;
	}

	switch ((cpids[1] = fork())) {
		case 0:
			exit(eventloop(fi, nfi, msg_fds[1]));
			break;
		case -1:
			err(1, "fork");
			break;
		default:
#ifndef NDEBUG
			fprintf(stderr, "event loop forked (%d)\n", cpids[1]);
#endif
			close(msg_fds[1]);
			nchildren++;
			break;
	}

	while (nchildren > 0) {
		int status;
		char *which = "none";
		pid_t chld = wait(&status);

		if (chld == cpids[0]) {
			which = "unbound updater";
		} else if (chld == cpids[1]) {
			which = "event loop";
		} else {
			which = "unknown";
		}

		fprintf(stderr, "Child %d (%s) exited with ", chld, which);
		if (WIFEXITED(status)) {
			fprintf(stderr, "status %d\n", WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "signal %d%s\n",
					WTERMSIG(status), WCOREDUMP(status)? " (core dumped)": "");
		}
		nchildren--;
	}

	return 0;
}
