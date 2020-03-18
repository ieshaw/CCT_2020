CC = gcc
lib = local_socket

lib: $(lib).o 
	ar rcs $(lib).a $^

.PHONY: clean

clean:
	rm *.o *.a
