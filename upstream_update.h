#ifndef _UNBOUND_UPDATE_H
#define _UNBOUND_UPDATE_H
#include "config.h"

enum upstream_msg_type {
	MSG_UPSTREAM_UPDATE
};

/* Packed message layout:
 * | type | nslen | lifetime | device | nameservers |
 */
struct upstream_update_msg {
	/* Source type this message originated from */
	enum srctype type;
	/* update life time, ~0 means infinity */
	uint32_t lifetime;
	/* Device these name servers come from */
	char *device;
	/* Total length of the name server list in this message */
	size_t nslen;
	/* sequence of '\0'-separated name server addresses */
	char *ns;
};

char *upstream_update_msg_pack(struct upstream_update_msg *, size_t *);
int upstream_update_msg_unpack(struct upstream_update_msg *, char *, size_t);
int upstream_update_msg_append_ns(struct upstream_update_msg *, const char *);
int upstream_update_loop(int, struct config*);
void upstream_update_msg_cleanup(struct upstream_update_msg *);
#endif /* _UNBOUND_UPDATE_H */
