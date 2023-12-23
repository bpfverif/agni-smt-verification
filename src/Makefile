CC=gcc
CFLAGS=-Wextra -Wall -g -fsanatize=address

DEPS=libbpf.o

%.o: %.c
	$(CC) -c $< -o $@

verifier_test: verifier_test.o $(DEPS) 
	$(CC) $^ -o $@

clean:
	rm *.o verifier_test

