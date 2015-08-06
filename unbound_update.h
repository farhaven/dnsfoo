#ifndef _UNBOUND_UPDATE_H
#define _UNBOUND_UPDATE_H
#include "config.h"

enum unbound_msg_type {
	MSG_UNBOUND_UPDATE
};

/* Packed message layout:
 * | type | nslen | lifetime | device | nameservers |
 */
struct unbound_update_msg {
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

char *unbound_update_msg_pack(struct unbound_update_msg *, size_t *);
int unbound_update_msg_unpack(struct unbound_update_msg *, char *, size_t);
int unbound_update_msg_append_ns(struct unbound_update_msg *, const char *);
int unbound_update_loop(int, struct config*);
void unbound_update_msg_cleanup(struct unbound_update_msg *);
#endif /* _UNBOUND_UPDATE_H */
