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
#include "serverrepo.h"

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
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			continue;
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

const char *srcnames[] = {
	[SRC_DHCPV4] = "DHCPv4",
	[SRC_RTADV]  = "RTADV",
};

int
main(void) {
	pid_t cpids[3] = { -1, -1, -1 };
	struct fileinfo *fi = NULL;
	struct source *sp;
	struct config *config;
	int nchildren = 0, nfi = 0;
	int msg_fds_handlers[2];
	int msg_fds_unbound[2];

	setproctitle(NULL);

	if ((config = parse_config("dnsfoo.conf")) == NULL) {
		errx(1, "Couldn't parse config");
	}
	TAILQ_FOREACH(sp, &config->sources, entry) {
		struct srcspec *src;
		TAILQ_FOREACH(src, &sp->specs->l, entry) {
			struct handler_info *info = NULL;
			fi = reallocarray(fi, nfi + 1, sizeof(*fi));
			if (src->type == SRC_DHCPV4) {
				info = dhcpv4_setup_handler(sp->device, src->source);
				fi[nfi].handler = dhcpv4_handle_update;
			} else if (src->type == SRC_RTADV) {
				info = rtadv_setup_handler(sp->device);
				fi[nfi].handler = rtadv_handle_update;
			} else {
				errx(1, "unknown source type %d", src->type);
			}
			if (info->sock < 0) {
				warn("failed to open %s handler for device %s",
				     srcnames[info->type], info->device);
				free(info->device);
				free(info);
				continue;
			}
			fi[nfi].fd = info->sock;
			EV_SET(&fi[nfi].ev, fi[nfi].fd, info->kq_event,
			       EV_ADD | EV_CLEAR, info->kq_note, 0, info);
			nfi++;
		}
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, msg_fds_handlers) == -1) {
		err(1, "socketpair");
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, msg_fds_unbound) == -1) {
		err(1, "socketpair");
	}

	cpids[0] = fork();
	if (cpids[0] == -1)
		err(1, "fork");
	else if (cpids[0] == 0)
		exit(unbound_update_loop(msg_fds_unbound[0]));
	else {
#ifndef NDEBUG
		fprintf(stderr, "unbound update loop forked (%d)\n", cpids[0]);
#endif
		nchildren++;
	}

	cpids[1] = fork();
	if (cpids[1] == -1)
		err(1, "fork");
	else if (cpids[1] == 0)
		exit(eventloop(fi, nfi, msg_fds_handlers[0]));
	else {
#ifndef NDEBUG
		fprintf(stderr, "event loop forked (%d)\n", cpids[1]);
#endif
		nchildren++;
	}

	cpids[2] = fork();
	if (cpids[2] == -1)
		err(1, "fork");
	else if (cpids[2] == 0)
		exit(serverrepo_loop(msg_fds_handlers[1], msg_fds_unbound[1]));
	else {
#ifndef NDEBUG
		fprintf(stderr, "server repo forked (%d)\n", cpids[2]);
#endif
		nchildren++;
	}

	close(msg_fds_unbound[0]);
	close(msg_fds_unbound[1]);
	close(msg_fds_handlers[0]);
	close(msg_fds_handlers[1]);

	while (nchildren > 0) {
		int status;
		char *which = "none";
		pid_t chld = wait(&status);

		if (chld == cpids[0]) {
			which = "unbound updater";
		} else if (chld == cpids[1]) {
			which = "event loop";
		} else if (chld == cpids[2]) {
			which = "server repo";
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
