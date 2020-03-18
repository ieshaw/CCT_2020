CC = gcc
modules = server client
libs = local_socket
libs_a = $(foreach lib,$(libs),$(wildcard $(lib)/$(lib).a))

client: client.o $(libs_a)
	$(CC) -o $@ $^ 
	./client 127.0.0.1 1337

.PHONY: clean

clean:
	rm $(modules) $(modules:%=%.o) 
