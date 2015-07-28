PROG= dnsfoo
SRCS= dnsfoo.c unbound_update.c handler_dhcpv4.c handler_rtadv.c parse.y conflex.l
MAN=

CFLAGS += -Wall -Werror -pedantic
CFLAGS += -std=c99
CFLAGS += -DYY_NO_UNPUT
LDADD += -lutil -lfl
DPADD += ${LIBUTIL}

.include <bsd.prog.mk>
