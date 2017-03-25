CC=clang

all: main libs

main: main.c
	$(CC) -o main main.c

libs: goodlib badlib

goodlib: printer.c
	$(CC) -Wall -dynamiclib -o libPrinter.dylib printer.c

badlib: bad_printer.c
	$(CC) -Wall -dynamiclib -o libBadPrinter.dylib bad_printer.c

clean:
	rm *.dylib
	rm main