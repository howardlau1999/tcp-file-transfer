#ifndef _UFTP_H_
#define _UFTP_H_

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "libsha1.h"

#define BUFFER_LEN 1024
#define MAX_WINDOW 4096
#define MAX_EVENTS 32
#define MAX_CONNS 32

struct filemetadata {
    uint64_t ctime;
    uint64_t filelen;
    unsigned char sha1[SHA1_DIGEST_SIZE];
    unsigned char fn[512];
};

typedef union {
    uint64_t read;
    uint64_t written;
} progress_t;

struct request {
    uint64_t offset;
    uint64_t length;
    int fd;
    progress_t progress;
};

static void print_hex(const char *data, size_t size) {
    int i;
    printf("0x");
    for (i = 0; i < size; ++i)
        printf("%x%x", ((unsigned char)data[i]) / 16,
               ((unsigned char)data[i]) % 16);
}

int get_in_port(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return (((struct sockaddr_in *)sa)->sin_port);
    }

    return (((struct sockaddr_in6 *)sa)->sin6_port);
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void set_non_blocking(int fd) {
    int opts;
    if ((opts = fcntl(fd, F_GETFL)) < 0) {
        fprintf(stderr, "GETFL failed");
        exit(1);
    }
    opts |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, opts) < 0) {
        fprintf(stderr, "SETFL failed");
        exit(1);
    }
}

void set_blocking(int fd) {
    int opts;
    if ((opts = fcntl(fd, F_GETFL)) < 0) {
        fprintf(stderr, "GETFL failed");
        exit(1);
    }
    opts &= ~O_NONBLOCK;
    if (fcntl(fd, F_SETFL, opts) < 0) {
        fprintf(stderr, "SETFL failed");
        exit(1);
    }
}

void recv_n(int fd, char *buf, const int size) {
    int received = 0;
    while (received < size) {
        int chunk = recv(fd, buf, size - received, 0);
        if (chunk == -1) {
            perror("recv");
            return;
        }
        received += chunk;
        buf += chunk;
    }
}

void send_n(int fd, const char *buf, const int size) {
    int sent = 0;
    while (sent < size) {
        int chunk = send(fd, buf, size - sent, 0);
        if (chunk == -1) {
            perror("send");
            return;
        }
        sent += chunk;
        buf += chunk;
    }
}

#endif