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

struct srcspec_l {
	TAILQ_HEAD(, srcspec) l;
};

struct source {
	char *device;
	struct srcspec_l *specs;
	TAILQ_ENTRY(source) entry;
};

struct config {
	TAILQ_HEAD(, source) sources;
};

struct config *parse_config(char *);
