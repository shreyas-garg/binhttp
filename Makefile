CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
CPPFLAGS += -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE

all: bserve bcurl

bserve: src/bserve.c src/bhttp.c src/bhttp.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ src/bserve.c src/bhttp.c

bcurl: src/bcurl.c src/bhttp.c src/bhttp.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ src/bcurl.c src/bhttp.c

test: all
	python3 tests/conformance.py

clean:
	rm -rf bserve bcurl *.dSYM

.PHONY: all test clean
