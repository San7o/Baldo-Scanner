all:
	nasm -f elf64 -o test_open.o test_open.s
	ld -m elf_x86_64 -o test_open.out test_open.o

clean:
	rm -f *.out *.o
