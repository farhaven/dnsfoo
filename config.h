#include <sys/queue.h>

enum srctype {
	SRC_DHCPV4,
	SRC_RTADV
};

struct srcspec {
	TAILQ_ENTRY(srcspec) entry;
	enum srctype type;
	char *source;
};

struct source {
	char *device;
	TAILQ_ENTRY(source) entry;
	TAILQ_HEAD(, srcspec) specs;
};

struct config {
	TAILQ_HEAD(, source) sources;
};

struct config *parse_config(char *);
