PROG= dnsfoo
SRCS= dnsfoo.c unbound_update.c handler_dhcpv4.c handler_rtadv.c parse.y
MAN=

CFLAGS += -Wall -Werror -pedantic
CFLAGS += -std=c99
LDADD += -lutil
DPADD += ${LIBUTIL}
YFLAGS=

.include <bsd.prog.mk>
