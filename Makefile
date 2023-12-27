SOURCES := $(wildcard vinylc/*.c)

default:
	gcc -o test.exe $(SOURCES)