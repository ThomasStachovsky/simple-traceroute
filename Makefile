CC = gcc
CFLAGS = -std=c99 -Wall -Wextra

all: traceroute
traceroute: main.o trace.o error.o
	gcc $(CFLAGS) -o traceroute $^
main.o: trace.h
trace.o: trace.h error.h
error.o: error.h

clean:
	rm -f *.o
distclean:
	rm -f *.o
	rm -f traceroute
