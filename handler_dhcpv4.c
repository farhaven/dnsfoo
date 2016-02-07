#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stdint.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <imsg.h>

#include "config.h"
#include "handlers.h"
#include "upstream_update.h"

void
dhcpv4_handle_update(int fd, int msg_fd, void *udata) {
	const char *match[] = { "option domain-name-servers", "option dhcp-lease-time" };
	struct handler_info *info = (struct handler_info*) udata;
	struct upstream_update_msg msg;
	struct imsgbuf ibuf;
	char *buf, *data;
	const char *errstr;
	FILE *f;
	size_t len;

	if (pledge("stdio rpath", NULL) < 0)
		err(1, "pledge");

	setproctitle("dhcpv4 lease parser");

	if ((f = fdopen(fd, "r")) == NULL) {
		err(1, "fdopen");
	}
	fseek(f, 0, SEEK_SET);

	memset(&msg, 0x00, sizeof(msg));
	msg.device = strdup(info->device);
	msg.lifetime = ~0;
	msg.type = info->type;

	/* Skip lines until we found the ones we're interested in */
	while ((data = fgetln(f, &len)) != NULL) {
		if (len <= 2) {
			continue;
		}

		/* The last char on a line is ';' which we don't need anyway */
		len -= 1;
		data[len - 1] = '\0';

		if ((buf = strstr(data, match[0])) != NULL) {
			/* Handle name servers */
			buf += strlen(match[0]) + 1;
			while (1) {
				char *p = strsep(&buf, ",");
				if (p == NULL)
					break;
				if (*p == '\0')
					continue;
				if (!upstream_update_msg_append_ns(&msg, p))
					err(1, "upstream_update_msg_append_ns");
				fprintf(stderr, "%llu: appended %s to list of name servers, list is now %ld bytes\n",
				        time(NULL), p, msg.nslen);
			}
		} else if ((buf = strstr(data, match[1])) != NULL) {
			/* Handle lifetime */
			long long lifetime = strtonum(buf + strlen(match[1]), 0, INT32_MAX, &errstr);
			if (errstr != NULL) {
				warn("%llu: The life time is %s", time(NULL), errstr);
				goto exit_fail;
			}
			msg.lifetime = (uint32_t) lifetime;
		}
	}

	if ((msg.nslen == 0) && ((msg.lifetime == 0) || (msg.lifetime == ~0))) {
		/* No interesting new information */
		return;
	}

	if ((data = upstream_update_msg_pack(&msg, &len)) == NULL)
		err(1, "upstream_update_msg_pack");
	imsg_init(&ibuf, msg_fd);
	if (imsg_compose(&ibuf, MSG_UPSTREAM_UPDATE, 0, 0, -1, data, len) < 0)
		err(1, "imsg_compose");
	free(data);
	upstream_update_msg_cleanup(&msg);

	do {
		if (msgbuf_write(&ibuf.w) > 0) {
			return;
		}
	} while (errno == EAGAIN);

exit_fail:
	upstream_update_msg_cleanup(&msg);
	err(1, "msgbuf_write");
}

struct handler_info *
dhcpv4_setup_handler(const char *device, const char *source) {
	struct handler_info *info = calloc(1, sizeof(*info));
	info->device = strdup(device);
	info->sock = open(source, O_RDONLY);
	info->kq_event = EVFILT_VNODE;
	info->kq_note  = NOTE_WRITE;
	info->type = SRC_DHCPV4;
	return info;
}
