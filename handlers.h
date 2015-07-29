#include <netinet/in.h>

#include "config.h"

struct handler_info {
	char *device;
	int kq_event;
	int kq_note;
	int sock;
	enum srctype type;
	union {
		struct {
			int ifindex;
			struct msghdr msghdr;
			struct sockaddr_in6 from;
		} rtadv;
	} v;
};

struct handler_info *dhcpv4_setup_handler(const char*, const char*);
void dhcpv4_handle_update(int, int, void*);

struct handler_info *rtadv_setup_handler(const char*);
void rtadv_handle_update(int, int, void*);
