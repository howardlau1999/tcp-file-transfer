#include "tftp.h"
#define MIN(a, b) ((a) < (b) ? (a) : (b))
int listen_port(const char *PORT) {
    struct addrinfo hints, *servinfo, *p;

    const int BACKLOG = MAX_CONNS;
    int rv, fd;
    int yes = 1;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket error");
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("server: setsockopt error");
            exit(1);
        }

        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            perror("server: bind error");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "server: failed to listen\n");
        exit(1);
    }

    if (listen(fd, BACKLOG) == -1) {
        close(fd);
        perror("server: listen error");
        exit(1);
    }

    return fd;
}

int main(int argc, char *argv[]) {
    int new_fd, server_fd, data_fd, filelen;

    struct sockaddr_storage clients_addr;
    socklen_t sin_size, addr_size;
    struct sigaction sa;
    const int TIMEOUT = 30000;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    char DATA_PORT[6] = {0};
    char *CNTL_PORT = argv[1];
    sprintf(DATA_PORT, "%d", atoi(argv[1]) + 1);

    FILE *fp;

    if (3 != argc) {
        fprintf(stderr, "usage: %s port filename\n", argv[0]);
        exit(1);
    }

    fp = fopen(argv[2], "r");
    unsigned char buffer[BUFFER_LEN], sendbuf[BUFFER_LEN];
    unsigned int n;

    puts("Calculating SHA1...");
    // Caculate SHA1 and length of the file
    sha1_ctx cx[1];
    unsigned char hval[SHA1_DIGEST_SIZE];

    sha1_begin(cx);
    while ((n = fread(buffer, 1, BUFFER_LEN, fp)) != 0) {
        sha1_hash(buffer, n, cx);
        filelen += n;
    }
    sha1_end(hval, cx);

    // Get file metadata
    struct stat metadata;
    fstat(fileno(fp), &metadata);

    if (!fp) {
        fprintf(stderr, "cannot open file %s\n", argv[2]);
    }

    struct filemetadata meta;
    meta.ctime = metadata.st_ctim.tv_sec;
    meta.filelen = filelen;
    strcpy(meta.fn, argv[2]);
    memcpy(meta.sha1, hval, SHA1_DIGEST_SIZE);

    server_fd = listen_port(CNTL_PORT);
    data_fd = listen_port(DATA_PORT);

    set_non_blocking(server_fd);
    set_non_blocking(data_fd);

    printf("Server listening on CNTL: %s DATA: %s\n", argv[1], DATA_PORT);

    int epoll_fd = epoll_create1(0);
    struct epoll_event events[MAX_EVENTS], cntl_conn_event, data_conn_event;
    int conns = 0;

    cntl_conn_event.events = EPOLLIN;
    cntl_conn_event.data.fd = server_fd;

    data_conn_event.events = EPOLLIN;
    data_conn_event.data.fd = data_fd;

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &cntl_conn_event);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, data_fd, &data_conn_event);

    sin_size = sizeof clients_addr;
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        if (nfds == -1) {
            fprintf(stderr, "epoll error\n");
            exit(1);
        }

        for (int i = 0; i < nfds; ++i) {
            struct epoll_event event = events[i];
            if (event.data.fd == server_fd && (event.events & EPOLLIN)) {
                int new_fd =
                    accept4(server_fd, (struct sockaddr *)&clients_addr,
                            &sin_size, SOCK_NONBLOCK);
                inet_ntop(clients_addr.ss_family,
                          get_in_addr((struct sockaddr *)&clients_addr), s,
                          sizeof s);
                printf("server: accepted control connection from %s:%d\n", s,
                       get_in_port((struct sockaddr *)&clients_addr));
                send(new_fd, &meta, sizeof(struct filemetadata), 0);
                close(new_fd);
            } else if (event.data.fd == data_fd && (event.events & EPOLLIN)) {
                int new_fd = accept4(data_fd, (struct sockaddr *)&clients_addr,
                                     &sin_size, SOCK_NONBLOCK);
                inet_ntop(clients_addr.ss_family,
                          get_in_addr((struct sockaddr *)&clients_addr), s,
                          sizeof s);
                printf("server: accepted data connection from %s:%d\n", s,
                       get_in_port((struct sockaddr *)&clients_addr));

                struct request *req = malloc(sizeof(struct request));
                req->fd = new_fd;
                struct epoll_event data_event = {0};
                data_event.events = EPOLLIN;
                data_event.data.ptr = req;

                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &data_event);
            } else if (event.events & EPOLLIN) {
                struct request *req = event.data.ptr;
                struct request req_recv;
                int fd = req->fd;
                recv(fd, &req_recv, sizeof(struct request), 0);
                req->length = req_recv.length;
                req->offset = req_recv.offset;
                req->progress.written = 0;
                printf("Fd: %d length=%ld offset=%ld\n", fd, req->length,
                       req->offset);

                event.events = EPOLLOUT;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
            } else if (event.events & EPOLLOUT) {
                struct request *req = event.data.ptr;
                int fd = req->fd;
                printf("Write %d\n", fd);
                fseek(fp, req->offset + req->progress.written, SEEK_SET);
                int size = fread(
                    buffer, 1,
                    MIN(BUFFER_LEN, req->length - req->progress.written), fp);
                while ((n = send(fd, buffer, size, 0)) > 0) {
                    req->progress.written += n;
                    printf("fd %d, written=%ld, offset=%ld\n", fd,
                           req->progress.written, req->offset);
                    if (req->progress.written == req->length) break;
                }

                if (req->progress.written == req->length) {
                    printf("fd %d finished, closing\n", fd);
                    close(fd);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &event);
                }
            }
        }
    }
}
