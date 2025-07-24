#include <client.h>
#include <metainfo.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <errno.h>
#include "peer.h"
#include "unity_fixture.h"
#include "unity.h"


static const char header_len = 19;
static const char *header = "BitTorrent protocol";
static const char header_reserved[8] = { 0 };

static struct client *client;
static struct metainfo_file torrent;
static unsigned char peer_id[20];


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


TEST_GROUP(listen_peers);

TEST_SETUP(listen_peers)
{
    TEST_ASSERT_EQUAL(1, RAND_bytes(peer_id, 20));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&torrent, "test/simple.torrent"));

    client = client_new(&torrent, 6881);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_NOT_EQUAL(0, client_peer_listener_start(client));
}

TEST_TEAR_DOWN(listen_peers)
{
    client_free(client);
    metainfo_file_free(&torrent);
    remove("sample.txt");
}

TEST(listen_peers, connect_ipv4)
{
    int sockfd;
    char buf[68];

    sockfd = client_connect("127.0.0.1", 6881);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);

    TEST_ASSERT_EQUAL(1, writen(sockfd, &header_len, 1));
    TEST_ASSERT_EQUAL(19, writen(sockfd, header, 19));
    TEST_ASSERT_EQUAL(8, writen(sockfd, header_reserved, 8));
    TEST_ASSERT_EQUAL(20, writen(sockfd, torrent.info_hash, 20));
    TEST_ASSERT_EQUAL(20, writen(sockfd, peer_id, 20));

    TEST_ASSERT_EQUAL(68, readn(sockfd, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);

    close(sockfd);
}

TEST(listen_peers, connect_ipv6)
{
    int sockfd;
    char buf[68];

    sockfd = client_connect("::1", 6881);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);

    TEST_ASSERT_EQUAL(1, writen(sockfd, &header_len, 1));
    TEST_ASSERT_EQUAL(19, writen(sockfd, header, 19));
    TEST_ASSERT_EQUAL(8, writen(sockfd, header_reserved, 8));
    TEST_ASSERT_EQUAL(20, writen(sockfd, torrent.info_hash, 20));
    TEST_ASSERT_EQUAL(20, writen(sockfd, peer_id, 20));

    TEST_ASSERT_EQUAL(68, readn(sockfd, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);

    close(sockfd);
}

TEST(listen_peers, peer_disconnect)
{
    int sockfd;

    sockfd = client_connect("127.0.0.1", 6881);
    TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);

    TEST_ASSERT_EQUAL(1, writen(sockfd, &header_len, 1));
    
    close(sockfd);
}

TEST(listen_peers, multiple_connecting_peers)
{
    int sockfd;
    char buf[68];

    for (int i = 0; i < 3; ++i) {
	TEST_ASSERT_EQUAL(1, RAND_bytes(peer_id, 20));

	sockfd = client_connect("127.0.0.1", 6881);
	TEST_ASSERT_GREATER_OR_EQUAL(0, sockfd);

	TEST_ASSERT_EQUAL(1, writen(sockfd, &header_len, 1));
	TEST_ASSERT_EQUAL(19, writen(sockfd, header, 19));
	TEST_ASSERT_EQUAL(8, writen(sockfd, header_reserved, 8));
	TEST_ASSERT_EQUAL(20, writen(sockfd, torrent.info_hash, 20));
	TEST_ASSERT_EQUAL(20, writen(sockfd, peer_id, 20));

	TEST_ASSERT_EQUAL(68, readn(sockfd, buf, 68));
	TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
	TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
	TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
	TEST_ASSERT_EQUAL_MEMORY(torrent.info_hash, buf + 28, 20);
	TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);

	close(sockfd);
    }
}


TEST_GROUP_RUNNER(listen_peers)
{
    RUN_TEST_CASE(listen_peers, connect_ipv4);
    RUN_TEST_CASE(listen_peers, connect_ipv6);

    RUN_TEST_CASE(listen_peers, peer_disconnect);
    RUN_TEST_CASE(listen_peers, multiple_connecting_peers);
}
