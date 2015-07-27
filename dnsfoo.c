#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/event.h>

#include "handlers.h"
#include "unbound_update.h"

struct fileinfo {
	int fd;
	void (*handler)(int, int);
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
		EV_SET(&ev, fi[idx].fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, NULL);

		if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
			err(1, "kevent");
		}
	}

	while (1) {
		pid_t child;

		if (kevent(kq, NULL, 0, &ev, 1, NULL) < 1) {
			err(1, "kevent");
		}

		switch ((child = fork())) {
			case 0:
				/* XXX: missing tame() and friends */
				for (idx = 0; idx < nfi; idx++) {
					if (ev.ident == fi[idx].fd) {
						fi[idx].handler(ev.ident, msg_fd);
						break;
					}
				}
				/* XXX: handle unknown ev.ident? */
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
	struct fileinfo fi[2];
	int nchildren = 0;
	int msg_fds[2];

	setproctitle(NULL);

	memset(&fi, 0x0, sizeof fi);

	fi[0].handler = handle_dhcpv4_update;
	fi[0].fd = open("/tmp/dnstest", O_RDONLY);
	if (fi[0].fd < 0) {
		err(1, "open(\"/tmp/dnstest\")");
	}

	fi[1].handler = handle_dhcpv4_update;
	fi[1].fd = open("/var/db/dhclient.leases.trunk0", O_RDONLY);
	if (fi[1].fd < 0) {
		err(1, "open(\"/var/db/dhclient.leases.trunk0\"");
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
			fprintf(stderr, "unbound update loop forked (%d)\n", cpids[0]);
			close(msg_fds[0]);
			nchildren++;
			break;
	}

	switch ((cpids[1] = fork())) {
		case 0:
			exit(eventloop(fi, sizeof(fi) / sizeof(fi[0]), msg_fds[1]));
			break;
		case -1:
			err(1, "fork");
			break;
		default:
			fprintf(stderr, "event loop forked (%d)\n", cpids[1]);
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
