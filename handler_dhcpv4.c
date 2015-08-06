#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stdint.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/tame.h>
#include <imsg.h>

#include "config.h"
#include "handlers.h"
#include "unbound_update.h"

void
dhcpv4_handle_update(int fd, int msg_fd, void *udata) {
	const char *match[] = { "option domain-name-servers", "option dhcp-renewal-time" };
	struct handler_info *info = (struct handler_info*) udata;
	struct unbound_update_msg msg;
	struct imsgbuf ibuf;
	char *buf, *data;
	const char *errstr;
	FILE *f;
	size_t len;

	tame(TAME_MALLOC | TAME_RPATH);

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
				if (!unbound_update_msg_append_ns(&msg, p))
					err(1, "unbound_update_msg_append_ns");
				fprintf(stderr, "appended %s to list of name servers, list is now %ld bytes\n", p, msg.nslen);
			}
		} else if ((buf = strstr(data, match[1])) != NULL) {
			/* Handle lifetime */
			long long lifetime = strtonum(buf + strlen(match[1]), 0, INT32_MAX, &errstr);
			if (errstr != NULL) {
				warn("The life time is %s", errstr);
				goto exit_fail;
			}
			msg.lifetime = (uint32_t) lifetime;
		}
	}

	if ((msg.nslen == 0) && ((msg.lifetime == 0) || (msg.lifetime == ~0))) {
		/* No interesting new information */
		return;
	}

	if ((data = unbound_update_msg_pack(&msg, &len)) == NULL)
		err(1, "unbound_update_msg_pack");
	imsg_init(&ibuf, msg_fd);
	if (imsg_compose(&ibuf, MSG_UNBOUND_UPDATE, 0, 0, -1, data, len) < 0)
		err(1, "imsg_compose");
	free(data);
	unbound_update_msg_cleanup(&msg);

	do {
		if (msgbuf_write(&ibuf.w) > 0) {
			return;
		}
	} while (errno == EAGAIN);

exit_fail:
	unbound_update_msg_cleanup(&msg);
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
