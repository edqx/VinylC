SOURCES := $(wildcard vinylc/*.c)

default:
	mkdir -p bin
	gcc -o bin/vinylc.exe $(SOURCES)

debug:
	mkdir -p bin
	gcc -ggdb -O0 -o bin/vinylc.exe $(SOURCES)