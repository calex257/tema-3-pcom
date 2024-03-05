CC=g++
CFLAGS=-I.

all:json.o client

json.o: json.cpp
	$(CC) -c -o json.o json.cpp

client: client.cpp requests.cpp helpers.cpp buffer.cpp json.o
	$(CC) -g -o client client.cpp requests.cpp helpers.cpp buffer.cpp json.o -Wall -Wno-write-strings -Wno-sign-compare

run: client
	./client

clean:
	rm -f *.o client
