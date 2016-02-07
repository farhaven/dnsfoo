PROG= dnsfoo
SRCS = dnsfoo.c upstream_update.c handler_dhcpv4.c handler_rtadv.c parse.y conflex.l
SRCS+= serverrepo.c
MAN=

CFLAGS += -Wall -Werror -pedantic
CFLAGS += -std=c99
CFLAGS += -g
LDADD += -lutil -lfl -lkvm
DPADD += ${LIBUTIL}

.include <bsd.prog.mk>
