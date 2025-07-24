#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <client.h>
#include <metainfo.h>
#include <sys/socket.h>
#include <bencode.h>
#include <errno.h>
#include <peer.h>
#include "unity_fixture.h"
#include "unity.h"


static const char header_len = 19;
static const char *header = "BitTorrent protocol";
static const char header_reserved[8] = { 0 };

static struct client *client;
static struct metainfo_file torrent;
static unsigned char peer_id[20];
static struct peer peer;

struct server_ctx {
    int family;
    uint16_t port;
    pthread_barrier_t barrier;
    int error;
    int conn;
    void (*callback)(int conn);
};


static ssize_t readn(int fd, void *buf, size_t n)
{
    size_t nleft = n;
    ssize_t nread;
    char *ptr = buf;

    while (nleft > 0) {
	if ((nread = read(fd, ptr, nleft)) < 0) {
	    if (errno == EINTR)
		continue;
	    else
		return -1;
	} else if (nread == 0) break;

	nleft -= nread;
	ptr += nread;
    }

    return n-nleft;
}

static ssize_t writen(int fd, const void *buf, size_t n)
{
    size_t nleft = n;
    const char *ptr = buf;
    ssize_t nwritten;

    while (nleft > 0) {
	if ((nwritten = write(fd, ptr, nleft)) <= 0) {
	    if (nwritten < 0 && errno == EINTR)
		nwritten = 0;
	    else
		return -1;
	}
	nleft -= nwritten;
	ptr += nwritten;
    }

    return n;
}

static void *server_run(void *args)
{
    struct server_ctx *ctx = args;
    struct sockaddr_in addr4 = { 0 };
    struct sockaddr_in6 addr6 = { 0 };
    struct sockaddr *addr;
    socklen_t len;
    int sockfd;
    int enable = 1;

    ctx->error = 0;
    if (ctx->family == AF_INET) {
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(ctx->port);
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	addr = (struct sockaddr *) &addr4;
	len = sizeof(addr4);
    } else if (ctx->family == AF_INET6) {
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(ctx->port);
	addr6.sin6_addr = in6addr_any;
	addr = (struct sockaddr *) &addr6;
	len = sizeof(addr6);
    } else {
	ctx->error = 1;
	pthread_barrier_wait(&ctx->barrier);
	return NULL;
    }

    sockfd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (sockfd < 0) {
	ctx->error = 1;
	pthread_barrier_wait(&ctx->barrier);
	return NULL;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0
	|| setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0
	|| bind(sockfd, addr, len) < 0
	|| listen(sockfd, 1) < 0) {
	ctx->error = 1;
	pthread_barrier_wait(&ctx->barrier);
	goto cleanup;
    }

    pthread_barrier_wait(&ctx->barrier);
    ctx->conn = accept(sockfd, NULL, NULL);
    if (ctx->conn >= 0 && ctx->callback != NULL) {
	ctx->callback(ctx->conn);
    }

 cleanup:
    close(sockfd);
    return NULL;
}

static int start_server(pthread_t *server, struct server_ctx *ctx)
{
    pthread_barrier_init(&ctx->barrier, NULL, 2);

    if (pthread_create(server, NULL, server_run, ctx) != 0) {
	pthread_barrier_destroy(&ctx->barrier);
	return 0;
    }

    pthread_barrier_wait(&ctx->barrier);
    pthread_barrier_destroy(&ctx->barrier);
    return ctx->error == 0;
}

static int client_connect(const char *address, uint16_t port)
{
    struct sockaddr_in addr4 = { 0 };
    struct sockaddr_in6 addr6 = { 0 };
    struct sockaddr *addr;
    socklen_t len;

    if (inet_pton(AF_INET, address, &addr4.sin_addr) == 1) {
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(port);
	addr = (struct sockaddr *) &addr4;
	len = sizeof(addr4);
    } else if (inet_pton(AF_INET6, address, &addr6.sin6_addr) == 1) {
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(port);
	addr = (struct sockaddr *) &addr6;
	len = sizeof(addr6);
    } else return -1;

    int sockfd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    if (connect(sockfd, addr, len) < 0) {
	close(sockfd);
	return -1;
    }

    return sockfd;
}

static void handshake(int conn)
{
    TEST_ASSERT_EQUAL(1, writen(conn, &header_len, 1));
    TEST_ASSERT_EQUAL(19, writen(conn, header, 19));
    TEST_ASSERT_EQUAL(8, writen(conn, header_reserved, 8));
    TEST_ASSERT_EQUAL(20, writen(conn, torrent.info_hash, 20));
    TEST_ASSERT_EQUAL(20, writen(conn, peer_id, 20));
}

static void close_connection(int conn)
{
    close(conn);
}

static void invalid_header_len(int conn)
{
    char len = 10;
    TEST_ASSERT_EQUAL(1, writen(conn, &len, 1));
    TEST_ASSERT_EQUAL(19, writen(conn, header, 19));
    TEST_ASSERT_EQUAL(8, writen(conn, header_reserved, 8));
    TEST_ASSERT_EQUAL(20, writen(conn, torrent.info_hash, 20));
    TEST_ASSERT_EQUAL(20, writen(conn, peer_id, 20));
}

static void invalid_header_content(int conn)
{
    TEST_ASSERT_EQUAL(1, writen(conn, &header_len, 1));
    TEST_ASSERT_EQUAL(19, writen(conn, "bittorrent protocol", 19));
    TEST_ASSERT_EQUAL(8, writen(conn, header_reserved, 8));
    TEST_ASSERT_EQUAL(20, writen(conn, torrent.info_hash, 20));
    TEST_ASSERT_EQUAL(20, writen(conn, peer_id, 20));
}

static void invalid_info_hash(int conn)
{
    char buf[20];

    memcpy(buf, torrent.info_hash, 20);
    buf[4] = 10;

    TEST_ASSERT_EQUAL(1, writen(conn, &header_len, 1));
    TEST_ASSERT_EQUAL(19, writen(conn, header, 19));
    TEST_ASSERT_EQUAL(8, writen(conn, header_reserved, 8));
    TEST_ASSERT_EQUAL(20, writen(conn, buf, 20));
    TEST_ASSERT_EQUAL(20, writen(conn, peer_id, 20));
}

static void slow_client(int conn)
{
    TEST_ASSERT_EQUAL(1, writen(conn, &header_len, 1));
    TEST_ASSERT_EQUAL(19, writen(conn, header, 19));
}


TEST_GROUP(handshake);

TEST_SETUP(handshake)
{
    TEST_ASSERT_EQUAL(1, RAND_bytes(peer_id, 20));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&torrent, "test/simple.torrent"));
    client = client_new(&torrent, 6881);
    TEST_ASSERT_NOT_NULL(client);
}

TEST_TEAR_DOWN(handshake)
{
    client_free(client);
    metainfo_file_free(&torrent);

    remove("sample.txt");
}


TEST(handshake, new_peer_ipv4)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = handshake
    };
    pthread_t server;
    int sockfd;
    char buf[68];

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));

    sockfd = client_connect("127.0.0.1", ctx.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_NOT_EQUAL(0, peer_init(&peer, client, sockfd));
    TEST_ASSERT_EQUAL(68, readn(ctx.conn, buf, 68));

    TEST_ASSERT_NOT_NULL(peer.peer_bitfield);
    TEST_ASSERT_NOT_NULL(peer.piece);
    TEST_ASSERT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_choking);
    TEST_ASSERT_NOT_EQUAL(0, peer.peer_choking);
    TEST_ASSERT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_EQUAL(0, peer.peer_interested);

    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);
    TEST_ASSERT_EQUAL_MEMORY(peer_id, peer.peer_id, 20);
    
    close(sockfd);
    close(ctx.conn);
    peer_free(&peer);
}

TEST(handshake, new_peer_ipv6)
{
    struct server_ctx ctx = {
	.family = AF_INET6,
	.port = 6882,
	.callback = handshake,
    };
    pthread_t server;
    int sockfd;
    char buf[68];

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));

    sockfd = client_connect("::1", ctx.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_NOT_EQUAL(0, peer_init(&peer, client, sockfd));
    TEST_ASSERT_EQUAL(68, readn(ctx.conn, buf, 68));

    TEST_ASSERT_NOT_NULL(peer.peer_bitfield);
    TEST_ASSERT_NOT_NULL(peer.piece);
    TEST_ASSERT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_choking);
    TEST_ASSERT_NOT_EQUAL(0, peer.peer_choking);
    TEST_ASSERT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_EQUAL(0, peer.peer_interested);

    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);

    close(sockfd);
    close(ctx.conn);
    peer_free(&peer);
}

TEST(handshake, peer_close_connection)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = close_connection
    };
    pthread_t server;
    int sockfd;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));

    sockfd = client_connect("127.0.0.1", ctx.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(0, peer_init(&peer, client, sockfd));
    
    close(sockfd);
}

TEST(handshake, new_peer_invalid_header_len)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = invalid_header_len
    };
    pthread_t server;
    int sockfd;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    sockfd = client_connect("127.0.0.1", ctx.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(0, peer_init(&peer, client, sockfd));

    close(sockfd);
}

TEST(handshake, new_peer_invalid_header_content)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = invalid_header_content
    };
    pthread_t server;
    int sockfd;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));

    sockfd = client_connect("127.0.0.1", ctx.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(0, peer_init(&peer, client, sockfd));

    close(sockfd);
}

TEST(handshake, new_peer_invalid_info_hash)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = invalid_info_hash
    };
    pthread_t server;
    int sockfd;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));

    sockfd = client_connect("127.0.0.1", ctx.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(0, peer_init(&peer, client, sockfd));

    close(sockfd);
}

TEST(handshake, new_peer_slow_client)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = slow_client
    };
    pthread_t server;
    int sockfd;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));

    sockfd = client_connect("127.0.0.1", ctx.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(0, peer_init(&peer, client, sockfd));

    close(sockfd);
}

TEST(handshake, peer_connect_ipv4)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = handshake,
    };
    pthread_t server;
    char buf[68];

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_NOT_EQUAL(0, peer_connect(&peer, client, "127.0.0.1", 6882));
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(68, readn(ctx.conn, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);
    TEST_ASSERT_EQUAL_MEMORY(peer_id, peer.peer_id, 20);

    TEST_ASSERT_NOT_NULL(peer.peer_bitfield);
    TEST_ASSERT_NOT_NULL(peer.piece);
    TEST_ASSERT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_choking);
    TEST_ASSERT_NOT_EQUAL(0, peer.peer_choking);
    TEST_ASSERT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_EQUAL(0, peer.peer_interested);

    close(ctx.conn);
    peer_free(&peer);
}

TEST(handshake, peer_connect_ipv6)
{
    struct server_ctx ctx = {
	.family = AF_INET6,
	.port = 6882,
	.callback = handshake,
    };
    pthread_t server;
    char buf[68];

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_NOT_EQUAL(0, peer_connect(&peer, client, "::1", 6882));
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(68, readn(ctx.conn, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);
    TEST_ASSERT_EQUAL_MEMORY(peer_id, peer.peer_id, 20);

    TEST_ASSERT_NOT_NULL(peer.peer_bitfield);
    TEST_ASSERT_NOT_NULL(peer.piece);
    TEST_ASSERT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_choking);
    TEST_ASSERT_NOT_EQUAL(0, peer.peer_choking);
    TEST_ASSERT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_EQUAL(0, peer.peer_interested);

    close(ctx.conn);
    peer_free(&peer);
}

TEST(handshake, peer_connect_close_connection)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = close_connection,
    };
    pthread_t server;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_EQUAL(0, peer_connect(&peer, client, "127.0.0.1", 6882));
    pthread_join(server, NULL);
    close(ctx.conn);
}

TEST(handshake, peer_connect_invalid_header_len)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = invalid_header_len,
    };
    pthread_t server;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_EQUAL(0, peer_connect(&peer, client, "127.0.0.1", 6882));
    pthread_join(server, NULL);
    close(ctx.conn);
}

TEST(handshake, peer_connect_invalid_header_content)
{
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = invalid_header_content,
    };
    pthread_t server;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_EQUAL(0, peer_connect(&peer, client, "127.0.0.1", 6882));
    pthread_join(server, NULL);
    close(ctx.conn);
}

TEST(handshake, peer_connect_invalid_info_hash)
{
    struct peer peer;
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = invalid_info_hash,
    };
    pthread_t server;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_EQUAL(0, peer_connect(&peer, client, "127.0.0.1", 6882));
    pthread_join(server, NULL);
    close(ctx.conn);
}

TEST(handshake, peer_connect_slow_client)
{
    struct peer peer;
    struct server_ctx ctx = {
	.family = AF_INET,
	.port = 6882,
	.callback = slow_client,
    };
    pthread_t server;

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_EQUAL(0, peer_connect(&peer, client, "127.0.0.1", 6882));
    pthread_join(server, NULL);
    close(ctx.conn);
}

TEST(handshake, peer_connect_dns)
{
    struct peer peer;
    struct server_ctx ctx = {
	.family = AF_INET6,
	.port = 6882,
	.callback = handshake,
    };
    pthread_t server;
    char buf[68];

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server, &ctx));
    TEST_ASSERT_NOT_EQUAL(0, peer_connect(&peer, client, "localhost", 6882));
    pthread_join(server, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx.conn);
    TEST_ASSERT_EQUAL(68, readn(ctx.conn, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);

    TEST_ASSERT_NOT_NULL(peer.peer_bitfield);
    TEST_ASSERT_NOT_NULL(peer.piece);
    TEST_ASSERT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_choking);
    TEST_ASSERT_NOT_EQUAL(0, peer.peer_choking);
    TEST_ASSERT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_EQUAL(0, peer.peer_interested);
    
    close(ctx.conn);
    peer_free(&peer);
}

TEST(handshake, peer_connect_invalid_dns)
{
    struct peer peer;

    TEST_ASSERT_EQUAL(0, peer_connect(&peer, client, "localhosteosds", 6882));
}

TEST(handshake, peer_connect_no_server)
{
    struct peer peer;

    TEST_ASSERT_EQUAL(0, peer_connect(&peer, client, "127.0.0.1", 6882));
}

TEST(handshake, multiple_peers)
{
    struct peer peer1, peer2;
    struct server_ctx ctx1 = {
	.family = AF_INET,
	.port = 6882,
	.callback = handshake
    };
    struct server_ctx ctx2 = {
	.family = AF_INET,
	.port = 6883,
	.callback = handshake
    };
    pthread_t server1, server2;
    int sockfd1, sockfd2;
    char buf[68];

    TEST_ASSERT_NOT_EQUAL(0, start_server(&server1, &ctx1));

    sockfd1 = client_connect("127.0.0.1", ctx1.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd1);
    pthread_join(server1, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx1.conn);
    TEST_ASSERT_NOT_EQUAL(0, peer_init(&peer1, client, sockfd1));

    TEST_ASSERT_EQUAL(68, readn(ctx1.conn, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);
    TEST_ASSERT_EQUAL_MEMORY(peer_id, peer1.peer_id, 20);

    TEST_ASSERT_EQUAL(1, RAND_bytes(peer_id, 20));
    TEST_ASSERT_NOT_EQUAL(0, start_server(&server2, &ctx2));

    sockfd2 = client_connect("127.0.0.1", ctx2.port);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd2);
    pthread_join(server2, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, ctx2.conn);

    TEST_ASSERT_NOT_EQUAL(0, peer_init(&peer2, client, sockfd2));

    TEST_ASSERT_EQUAL(68, readn(ctx2.conn, buf, 68));

    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);
    TEST_ASSERT_EQUAL_MEMORY(peer_id, peer2.peer_id, 20);

    close(sockfd1);
    close(ctx1.conn);
    close(sockfd2);
    close(ctx2.conn);
    peer_free(&peer1);
    peer_free(&peer2);
}


TEST_GROUP_RUNNER(handshake)
{
    RUN_TEST_CASE(handshake, new_peer_ipv4);
    RUN_TEST_CASE(handshake, new_peer_ipv6);

    RUN_TEST_CASE(handshake, peer_close_connection);

    RUN_TEST_CASE(handshake, new_peer_invalid_header_len);
    RUN_TEST_CASE(handshake, new_peer_invalid_header_content);
    RUN_TEST_CASE(handshake, new_peer_invalid_info_hash);
    RUN_TEST_CASE(handshake, new_peer_slow_client);

    RUN_TEST_CASE(handshake, peer_connect_ipv4);
    RUN_TEST_CASE(handshake, peer_connect_ipv6);
    RUN_TEST_CASE(handshake, peer_connect_dns);
    RUN_TEST_CASE(handshake, peer_connect_close_connection);

    RUN_TEST_CASE(handshake, peer_connect_invalid_dns);
    RUN_TEST_CASE(handshake, peer_connect_no_server);

    RUN_TEST_CASE(handshake, peer_connect_invalid_header_len);
    RUN_TEST_CASE(handshake, peer_connect_invalid_header_content);
    RUN_TEST_CASE(handshake, peer_connect_invalid_info_hash);
    RUN_TEST_CASE(handshake, peer_connect_slow_client);

    RUN_TEST_CASE(handshake, multiple_peers);
}
