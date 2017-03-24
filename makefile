CC=clang

all: main libs

main:
	$(CC) -o main main.c

libs: goodlib badlib

goodlib:
	$(CC) -Wall -dynamiclib -o libPrinter.dylib printer.c

badlib:
	$(CC) -Wall -dynamiclib -o libBadPrinter.dylib bad_printer.c

clean:
	rm *.dylib
	rm main