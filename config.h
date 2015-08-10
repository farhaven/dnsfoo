#ifndef _CONFIG_H
#define _CONFIG_H
#include <pwd.h>
#include <sys/queue.h>

enum srctype {
	SRC_DHCPV4,
	SRC_RTADV,
	SRC_UNKNOWN
};

struct srcspec {
	TAILQ_ENTRY(srcspec) entry;
	enum srctype type;
	char *source;
};

struct srcspec_l {
	TAILQ_HEAD(, srcspec) l;
};

struct device {
	char *device;
	struct srcspec_l *specs;
	TAILQ_ENTRY(device) entry;
};

struct config {
	TAILQ_HEAD(, device) devices;
	struct passwd *pw;
};

typedef struct {
	union {
		char *string;
		struct srcspec *spec;
		struct srcspec_l *spec_l;
	} v;
	int lineno;
} YYSTYPE;

struct config *parse_config(char *);
#endif /* _CONFIG_H */
