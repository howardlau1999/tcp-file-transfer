all: server client
%.o: %.c tftp.h
	gcc -g -c $< -o $@

server: server.o sha1.o
	gcc -g $^ -o $@

client: client.o sha1.o
	gcc -g $^ -o $@

clean:
	rm *.o

.PHONY: clean