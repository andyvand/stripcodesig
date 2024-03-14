CC=clang
CODESIGN=codesign -f -s "Apple Development"
#CODESIGN=codesign -f -s "-"
CFLAGS=-arch arm64 -arch x86_64 -O3

all: stripcodesig

stripcodesig: stripcodesig.c
	$(CC) $(CFLAGS) -I. -o $@ $<
	$(CODESIGN) $@

clean:
	rm -f stripcodesig

install: stripcodesig
	cp -f stripcodesig /usr/local/bin/

