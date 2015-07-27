CFLAGS += -g -pedantic -Werror -Wall -std=c99
LDFLAGS += -g -lutil

dnsfoo: dnsfoo.o unbound_update.o handler_dhcpv4.o handler_rtadv.o
	$(CC) $(LDFLAGS) -o dnsfoo $(.ALLSRC)

clean:
	rm -f dnsfoo *.o
