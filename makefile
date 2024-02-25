CC = g++
CFLAGS = -lssl -lcrypto -pthread

all: client server

client: client.cpp
	$(CC) -o client client.cpp $(CFLAGS)

server: server.cpp
	$(CC) -o server server.cpp $(CFLAGS)

clean:
	rm -f client server