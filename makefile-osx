CC=clang

all: main libs

main: main.c
	$(CC) -lcrypto -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o main main.c

libs: goodlib badlib

goodlib: printer.c
	$(CC) -Wall -dynamiclib -o libPrinter.dylib printer.c

badlib: bad_printer.c
	$(CC) -Wall -dynamiclib -o libBadPrinter.dylib bad_printer.c

clean:
	rm *.dylib
	rm main