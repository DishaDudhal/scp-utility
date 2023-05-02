CC = gcc
#CFLAGS = -Wall -Wextra -pedantic -std=c99
LIBS = `pkg-config --cflags --libs libgcrypt`

all: purenc purdec
.PHONY : all
purenc: purenc-new.c
	$(CC) -o $@ $< $(LIBS)

purdec: purdec.c
	$(CC) -o $@ $< $(LIBS)

clean:
	rm -f purenc purdec