#include "tftp.h"

int connect_to(const char *host, const char *port) {
    struct addrinfo hints, *servinfo, *p;
    int rv, fd;
    char s[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket error");
            continue;
        }

        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            perror("client: connect error");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        exit(2);
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)&p->ai_addr), s,
              sizeof s);
    fprintf(stdout, "client: connected to %s:%s\n", s, port);
    freeaddrinfo(servinfo);
    return fd;
}

int main(int argc, char *argv[]) {
    int numbytes = 0;
    char buf[BUFFER_LEN];
    struct filemetadata meta;
    int client_fd;

    int conns = 8;

    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s hostname port filename [conns]\n", argv[0]);
        exit(1);
    }

    FILE *fp = fopen(argv[3], "w");

    if (argc == 5) {
        conns = atoi(argv[4]);
    }

    char *CNTL_PORT = argv[2];
    char *HOST = argv[1];
    char DATA_PORT[6] = {0};
    sprintf(DATA_PORT, "%d", atoi(CNTL_PORT) + 1);

    int cntl_fd = connect_to(argv[1], CNTL_PORT);
    recv_n(cntl_fd, buf, sizeof(struct filemetadata));
    memcpy(&meta, buf, sizeof(struct filemetadata));
    printf("Filename: %s\n", meta.fn);
    printf("Length: %lu\n", meta.filelen);
    printf("Create Time: %lu\n", meta.ctime);
    printf("SHA1: ");
    print_hex(meta.sha1, SHA1_DIGEST_SIZE);
    puts("");

    int length_per_conn = meta.filelen / conns;
    int remain = meta.filelen % conns;

    int epoll_fd = epoll_create1(0);
    struct epoll_event events[MAX_EVENTS];
    struct request *reqs = malloc(sizeof(struct request) * conns);

    printf("starting %d data connections...\n", conns);

    for (int i = 0; i < conns; ++i) {
        int data_fd = connect_to(HOST, DATA_PORT);
        set_non_blocking(data_fd);
        struct epoll_event data_event = {0};

        struct request *req = &reqs[i];
        req->fd = data_fd;
        req->offset = i * length_per_conn;
        req->length = length_per_conn;
        if (i == conns - 1) req->length += remain;
        req->progress.read = 0;

        data_event.data.ptr = req;
        data_event.events = EPOLLOUT;

        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, data_fd, &data_event);
    }

    struct timeval tik, tok;

    gettimeofday(&tik, NULL);

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        if (nfds == -1) {
            fprintf(stderr, "epoll error\n");
        }

        for (int i = 0; i < nfds; ++i) {
            struct epoll_event event = events[i];
            struct request *req = event.data.ptr;
            int fd = req->fd;
            if (event.events & EPOLLOUT) {
                int n = send(fd, req, sizeof(struct request), 0);
                event.events = EPOLLIN;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
            } else if (event.events & EPOLLIN) {
                int n;
                while ((n = recv(fd, buf, BUFFER_LEN, 0)) > 0) {
                    fseek(fp, req->offset + req->progress.read, SEEK_SET);
                    fwrite(buf, 1, n, fp);
                    req->progress.read += n;
                    numbytes += n;
                    if (req->progress.read == req->length) break;
                }

                if (req->progress.read == req->length) {
                    close(fd);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &event);
                }
            }
        }

        gettimeofday(&tok, NULL);
        uint64_t elapsed = (tok.tv_usec + tok.tv_sec * 1000000) - (tik.tv_usec + tik.tv_sec * 1000000);
        printf("\rBytes received: %d/%ld  Speed: %.2lf bytes/sec", numbytes,
               meta.filelen, (double)numbytes / elapsed * 1000000);
        fflush(stdout);
        if (numbytes >= meta.filelen) break;
    }
    puts("");

    printf("File transfer finished\n");

    fclose(fp);

    int n = 0, filelen = 0;
    fp = fopen(argv[3], "r");

    puts("");

    unsigned char buffer[BUFFER_LEN];
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

    if (filelen != meta.filelen) {
        printf("File Length mismatched!\n");
        exit(1);
    }

    if (memcmp(hval, meta.sha1, SHA1_DIGEST_SIZE)) {
        printf("SHA1 mismatched!");
        printf("Expected: ");
        print_hex(meta.sha1, SHA1_DIGEST_SIZE);
        puts("");

        printf("Actual: ");
        print_hex(hval, SHA1_DIGEST_SIZE);
        puts("");
        exit(1);
    }

    puts("Everything seems ok.");
}