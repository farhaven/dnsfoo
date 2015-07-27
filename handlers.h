#include <netinet/in.h>

struct rtadv_info {
	int sock;
	int ifindex;
	struct sockaddr_in6 from;
	struct msghdr msghdr;
};

void dhcpv4_handle_update(int, int, void*);

struct rtadv_info *rtadv_setup_handler(const char*);
void rtadv_handle_update(int, int, void*);
