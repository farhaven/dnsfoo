CFLAGS += -g -pedantic -Werror -Wall
LDFLAGS += -g -lutil

dnsfoo: dnsfoo.o unbound_update.o
	$(CC) $(LDFLAGS) -o dnsfoo $(.ALLSRC)

clean:
	rm -f dnsfoo
