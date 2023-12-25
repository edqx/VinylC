SOURCES := $(wildcard *.c)

default:
	gcc -o test.exe $(SOURCES)