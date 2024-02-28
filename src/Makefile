CC=gcc
CFLAGS=-Wextra -Wall -g

DEPS=libbpf.o

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o  ../bin/$@

verifier_test: verifier_test.o $(DEPS) 
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm *.o verifier_test

