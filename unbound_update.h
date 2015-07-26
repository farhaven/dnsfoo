#ifndef _UNBOUND_UPDATE_H
#define _UNBOUND_UPDATE_H
enum unbound_msg_type {
	MSG_UNBOUND_UPDATE
};

int unbound_update_loop(int);
#endif /* _UNBOUND_UPDATE_H */
