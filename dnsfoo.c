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
	int kq, status;
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

		child = fork();

		if (child == -1)
			err(1, "fork");
		else if (child == 0) {
			for (idx = 0; idx < nfi; idx++) {
				if (ev.ident != fi[idx].fd)
					continue;
				fi[idx].handler(ev.ident, msg_fd, ev.udata);
				exit(0);
			}

			err(1, "Unknown file handle %d", (int) ev.ident);
		}

		waitpid(child, &status, 0);
#ifndef NDEBUG
		fprintf(stderr, "Event handler %d exited with ", child);
		if (WIFEXITED(status)) {
			fprintf(stderr, "status %d\n", WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "signal %d%s\n",
			        WTERMSIG(status),
			        WCOREDUMP(status)? " (core dumped)": "");
		}
#endif
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
		TAILQ_FOREACH(src, &sp->specs->l, entry) {
			fi = reallocarray(fi, nfi + 1, sizeof(*fi));
			if (src->type == SRC_DHCPV4) {
				fi[nfi].handler = dhcpv4_handle_update;
				fi[nfi].fd = open(src->source, O_RDONLY);
				if (fi[nfi].fd < 0) {
					warn("open(\"%s\")", src->source);
					continue;
				}
				EV_SET(&fi[nfi].ev, fi[nfi].fd, EVFILT_VNODE,
				       EV_ADD | EV_CLEAR, NOTE_WRITE, 0, NULL);
			} else if (src->type == SRC_RTADV) {
				ri = rtadv_setup_handler(sp->device);
				fi[nfi].handler = rtadv_handle_update;
				fi[nfi].fd = ri->sock;
				EV_SET(&fi[nfi].ev, fi[nfi].fd, EVFILT_READ,
				       EV_ADD | EV_CLEAR, 0, 0, ri);
			} else {
				errx(1, "unknown source type %d", src->type);
			}
			nfi++;
		}
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, msg_fds) == -1) {
		err(1, "socketpair");
	}

	cpids[0] = fork();
	if (cpids[0] == -1)
		err(1, "fork");
	else if (cpids[0] == 0)
		exit(unbound_update_loop(msg_fds[0]));
	else {
#ifndef NDEBUG
		fprintf(stderr, "unbound update loop forked (%d)\n", cpids[0]);
#endif
		close(msg_fds[0]);
		nchildren++;
	}

	cpids[1] = fork();
	if (cpids[1] == -1)
		err(1, "fork");
	else if (cpids[1] == 0)
		exit(eventloop(fi, nfi, msg_fds[1]));
	else {
#ifndef NDEBUG
		fprintf(stderr, "event loop forked (%d)\n", cpids[1]);
#endif
		close(msg_fds[1]);
		nchildren++;
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
			        WTERMSIG(status),
			        WCOREDUMP(status)? " (core dumped)": "");
		}
		nchildren--;
	}

	return 0;
}
