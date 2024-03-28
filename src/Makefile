CC=gcc
CFLAGS=-Wextra -Wall -g

DEPS=libbpf.o

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

kernel_verifier: kernel_verifier.o $(DEPS) 
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm *.o verifier_test

