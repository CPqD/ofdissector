#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define HOST "localhost"
#define PORT 6633

// 8
static inline uint8_t
hton8(uint8_t n) {
    return n;
}

static inline uint8_t
ntoh8(uint8_t n) {
    return n;
}

// 16
static inline uint16_t
hton16(uint16_t n) {
    return htons(n);
}

static inline uint16_t
ntoh16(uint16_t n) {
    return ntohs(n);
}

// 32
static inline uint32_t
hton32(uint32_t n) {
    return htonl(n);
}

static inline uint32_t
ntoh32(uint32_t n) {
    return ntohl(n);
}

// 64
static inline uint64_t
hton64(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

static inline uint64_t
ntoh64(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)ntohl(n)) << 32) + ntohl(n >> 32);
#endif
}


void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}
