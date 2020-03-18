CC = gcc
modules = server client
libs = local_socket
libs_a = $(foreach lib,$(libs),$(wildcard $(lib)/$(lib).a))

client: client.o $(libs_a)
	$(CC) -o $@ $^ 
	./client

.PHONY: clean

clean:
	rm $(modules) $(modules:%=%.o) 
