#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <sys/queue.h>
#include <sys/uio.h>
#include <imsg.h>

#include "unbound_update.h"

void
parse_dhclient_lease(int fd, int msg_fd) {
	const char *match = "option domain-name-servers";
	struct imsgbuf ibuf;
	char *buf, *data;
	FILE *f;
	size_t len;

	setproctitle("dhcpv4 lease parser");

	if ((f = fdopen(fd, "r")) == NULL) {
		err(1, "fdopen");
	}
	fseek(f, 0, SEEK_SET);

	/* Skip lines until we found the one we're interested in */
	while ((buf = fgetln(f, &len)) != NULL) {
		if (len <= strlen(match) + 1) {
			continue;
		}

		/* The last char on a line is ';' which we don't need anyway */
		len -= 1;
		buf[len - 1] = '\0';

		if ((buf = strstr(buf, match)) == NULL) {
			continue;
		}

		buf += strlen(match) + 1;

		/* The rest of the file isn't interesting, let's skip it */
		break;
	}
	if (buf == NULL) {
		fprintf(stderr, "No DNS info found :/\n");
		return;
	}

	/* Copy data to a safe space */
	data = calloc(strlen(buf) + 1, sizeof(char));
	if (data == NULL) {
		err(1, "calloc");
	}
	(void)strlcpy(data, buf, strlen(buf) + 1);

	fprintf(stderr, "dns info: \"%s\" (%ld)\n", data, strlen(data));

	imsg_init(&ibuf, msg_fd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, data, strlen(data) + 1) < 0)
		err(1, "imsg_compose");

	do {
		if (msgbuf_write(&ibuf.w) > 0) {
			return;
		}
	} while (errno == EAGAIN);
	err(1, "msgbuf_write");
}

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
				parse_dhclient_lease(ev.ident, msg_fd);
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
	}

	return 0;
}
