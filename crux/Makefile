.PHONY: all crux kernel.o

all: crux

crux: kernel.o entry.o hypercalls.o malloooc.o
	clang entry.o hypercalls.o malloooc.o kernel.o -o crux; /usr/local/opt/binutils/bin/objcopy -Obinary crux

entry.o:
	nasm entry.s -fmacho64

hypercalls.o:
	nasm hypercalls.s -fmacho64

kernel.o:
	clang -ffreestanding -nostdlib  kernel.c  -c -g

malloooc.o:
	clang -ffreestanding -nostdlib mem/malloc.c  -Imem -c -o malloooc.o -g

clean:
	rm *.o crux

