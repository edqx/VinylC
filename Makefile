SOURCES := $(wildcard vinylc/*.c)

default:
	gcc -ggdb -O0 -o test.exe $(SOURCES)