# Multi-connection TCP File Transfer

This simple project allows clients to download a file from server via multiple parellel TCP connections.

# Build & Run

Build by simply `make`.

Server:

```bash
./server port file-to-serve
```

Client:

```bash
./client hostname port local-filename [tcp-connections-count (default:8)]
```

Note the project uses PORT and PORT + 1 for control message and data transfer respectively. For example, if you specify port 9315 while starting server, it will use port 9315 to accept new clients and use port 9316 for further data transfer.
