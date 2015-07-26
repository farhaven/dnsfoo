#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/event.h>

#include "handlers.h"
#include "unbound_update.h"

int
eventloop(int fd, int msg_fd) {
	struct kevent ev;
	int kq;

	setproctitle("event loop");

	if ((kq = kqueue()) < 0) {
		err(1, "kqueue");
	}

	EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, NULL);

	if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
		err(1, "kevent");
	}

	while (1) {
		pid_t child;

		if (kevent(kq, NULL, 0, &ev, 1, NULL) < 1) {
			err(1, "kevent");
		}

		switch ((child = fork())) {
			case 0:
				/* XXX: missing tame() and friends */
				handle_dhcpv4_update(ev.ident, msg_fd);
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
	int nchildren = 0;
	int msg_fds[2];

	int dhcp4_fd;

	setproctitle(NULL);

	dhcp4_fd = open("/tmp/dnstest", O_RDONLY);
	if (dhcp4_fd < 0) {
		err(1, "open(\"/tmp/dnstest\")");
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
			exit(eventloop(dhcp4_fd, msg_fds[1]));
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
