#include <pthread.h>
#include <peer.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <client.h>
#include "metainfo.h"
#include "unity_fixture.h"
#include "unity.h"

static struct peer peer;
static pthread_t srvthrd;
static int srvsock;
static int conn_srv;

static struct metainfo_file torrent;


static void *accept_connection(void *args)
{
    conn_srv = accept(srvsock, NULL, NULL);
    return NULL;
}

static int start_server(void)
{
    struct sockaddr_in addr = { 0 };
    int enable = 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(6882);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srvsock = socket(AF_INET, SOCK_STREAM, 0);
    if (srvsock < 0) return 0;
    if (setsockopt(srvsock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0
	|| setsockopt(srvsock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0
	|| bind(srvsock, (struct sockaddr *) &addr, sizeof(addr)) < 0
	|| listen(srvsock, 1) < 0)
	return 0;

    return pthread_create(&srvthrd, NULL, accept_connection, NULL) == 0;
}

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

static int client_connect(void)
{
    struct sockaddr_in addr = { 0 };

    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6882);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	close(sockfd);
	return -1;
    }

    return sockfd;
}

static int copy_file(const char *src, const char *dst)
{
    int c;
    FILE *fp1 = fopen(src, "rb");
    if (fp1 == NULL) return 0;

    FILE *fp2 = fopen(dst, "wb");
    if (fp2 == NULL) {
	fclose(fp1);
	return 0;
    }

    while ((c = fgetc(fp1)) != EOF)
	fputc(c, fp2);

    fclose(fp1);
    fclose(fp2);

    return 1;
}

static void client_init(const char *file)
{
    char buf[strlen(file) + 14];

    sprintf(buf, "test/%s", file);
    copy_file(buf, file);

    sprintf(buf, "test/%s.torrent", file);
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&torrent, buf));

    peer.client = client_new(&torrent, 6881);
    TEST_ASSERT_NOT_NULL(peer.client);

    uint32_t len = metainfo_file_pieces_count(&torrent);
    len = len/8 + (len%8 ? 1 : 0);

    peer.peer_bitfield = calloc(len, 1);
    TEST_ASSERT_NOT_NULL(peer.peer_bitfield);

    peer.piece = malloc(torrent.info.piece_length);
    TEST_ASSERT_NOT_NULL(peer.piece);
}


TEST_GROUP(peer_proto);

TEST_SETUP(peer_proto)
{
    TEST_ASSERT_NOT_EQUAL(0, start_server());
    peer.sockfd = client_connect();
    TEST_ASSERT_GREATER_OR_EQUAL(0, peer.sockfd);
    pthread_join(srvthrd, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, conn_srv);
    peer.peer_bitfield = NULL;
    peer.piece = NULL;
    peer.client = NULL;
    peer.has_reserved = 0;
    peer.am_choking = 1;
    peer.am_interested = 0;
    peer.peer_choking = 1;
    peer.peer_interested = 0;
    peer.waiting_piece = 0;
}

TEST_TEAR_DOWN(peer_proto)
{
    close(srvsock);
    close(conn_srv);
    close(peer.sockfd);
    if (peer.client != NULL) {
	client_free(peer.client);
	metainfo_file_free(&torrent);
    }
    if (peer.peer_bitfield != NULL)
	free(peer.peer_bitfield);
    if (peer.piece != NULL)
	free(peer.piece);
    remove("existing_file_len_non_multiple");
    remove("incomplete_file_len_non_multiple");
    remove("not_existing");
    remove("piece_requests");
}

TEST(peer_proto, send_choke)
{
    unsigned char buf[5];

    TEST_ASSERT_NOT_EQUAL(0, peer_send_choke(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(0, buf[4]);
    TEST_ASSERT_NOT_EQUAL(0, peer.peer_choking);
}

TEST(peer_proto, send_unchoke)
{
    unsigned char buf[5];

    TEST_ASSERT_NOT_EQUAL(0, peer_send_unchoke(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(1, buf[4]);
    TEST_ASSERT_EQUAL(0, peer.peer_choking);
}

TEST(peer_proto, send_interested)
{
    unsigned char buf[5];

    TEST_ASSERT_NOT_EQUAL(0, peer_send_interested(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(2, buf[4]);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_interested);
}

TEST(peer_proto, send_not_interested)
{
    unsigned char buf[5];

    TEST_ASSERT_NOT_EQUAL(0, peer_send_not_interested(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(3, buf[4]);
    TEST_ASSERT_EQUAL(0, peer.am_interested);
}

TEST(peer_proto, send_have)
{
    unsigned char buf[9];

    TEST_ASSERT_NOT_EQUAL(0, peer_send_have(&peer, 2));
    TEST_ASSERT_EQUAL(9, readn(conn_srv, buf, 9));
    TEST_ASSERT_EQUAL(5, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(4, buf[4]);
    TEST_ASSERT_EQUAL(2, ntohl(*((uint32_t *) (buf + 5))));
}

TEST(peer_proto, send_bitfield_complete)
{
    unsigned char buf[6];

    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_NOT_EQUAL(0, peer_send_bitfield(&peer));
    TEST_ASSERT_EQUAL(6, readn(conn_srv, buf, 6));
    TEST_ASSERT_EQUAL(2, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(5, buf[4]);
    TEST_ASSERT_EQUAL(0b11100000, buf[5]);
}

TEST(peer_proto, send_bitfield_empty)
{
    unsigned char buf[2707];
    unsigned char expected[2702] = { 0 };

    client_init("not_existing");
    TEST_ASSERT_NOT_EQUAL(0, peer_send_bitfield(&peer));
    TEST_ASSERT_EQUAL(2707, readn(conn_srv, buf, 2707));
    TEST_ASSERT_EQUAL(2703, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(5, buf[4]);
    TEST_ASSERT_EQUAL_MEMORY(expected, buf + 5, 2702);
}

TEST(peer_proto, send_bitfield_incomplete)
{
    unsigned char buf[6];

    client_init("incomplete_file_len_non_multiple");
    TEST_ASSERT_NOT_EQUAL(0, peer_send_bitfield(&peer));
    TEST_ASSERT_EQUAL(6, readn(conn_srv, buf, 6));
    TEST_ASSERT_EQUAL(2, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(5, buf[4]);
    TEST_ASSERT_EQUAL(0b01000000, buf[5]);
}

TEST(peer_proto, send_request)
{
    unsigned char buf[17];

    TEST_ASSERT_NOT_EQUAL(0, peer_send_request(&peer, 2, 16384, 16332));
    TEST_ASSERT_EQUAL(17, readn(conn_srv, buf, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(6, buf[4]);
    TEST_ASSERT_EQUAL(2, ntohl(*((uint32_t *) (buf + 5))));
    TEST_ASSERT_EQUAL(16384, ntohl(*((uint32_t *) (buf + 9))));
    TEST_ASSERT_EQUAL(16332, ntohl(*((uint32_t *) (buf + 13))));
}

TEST(peer_proto, send_piece)
{
    unsigned char buf[16];
    unsigned char expected[] = { 0xfb, 0xb3, 0x0b };

    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_NOT_EQUAL(0, peer_send_piece(&peer, 1, 1, 3));
    TEST_ASSERT_EQUAL(16, readn(conn_srv, buf, 16));
    TEST_ASSERT_EQUAL(12, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(7, buf[4]);
    TEST_ASSERT_EQUAL(1, ntohl(*((uint32_t *) (buf + 5))));
    TEST_ASSERT_EQUAL(1, ntohl(*((uint32_t *) (buf + 9))));
    TEST_ASSERT_EQUAL_MEMORY(expected, buf + 13, 3);
    TEST_ASSERT_EQUAL(3, client_uploaded(peer.client));
}

TEST(peer_proto, recv_choke)
{
    struct peer other = { .sockfd = conn_srv };

    peer.am_choking = 0;
    TEST_ASSERT_NOT_EQUAL(0, peer_send_choke(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_NOT_EQUAL(0, peer.am_choking);
}

TEST(peer_proto, recv_keepalive)
{
    char keepalive[] = { 0x00, 0x00, 0x00, 0x00 };

    TEST_ASSERT_EQUAL(4, writen(conn_srv, keepalive, 4));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
}

TEST(peer_proto, recv_bitfield_complete_choked)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0xe0 };

    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL_MEMORY(bitfield + 5, peer.peer_bitfield, 1);
}

TEST(peer_proto, recv_bitfield_complete_unchoked)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0xe0 };

    peer.am_choking = 0;
    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL_MEMORY(bitfield + 5, peer.peer_bitfield, 1);
}

TEST(peer_proto, recv_bitfield_incomplete_choked)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0xe0 };
    unsigned char buf[5];

    client_init("incomplete_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(2, buf[4]);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_EQUAL_MEMORY(bitfield + 5, peer.peer_bitfield, 1);
}

TEST(peer_proto, recv_bitfield_incomplete_unchoked)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0xe0 };
    unsigned char buf[17];

    peer.am_choking = 0;
    client_init("incomplete_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(2, buf[4]);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_EQUAL(17, readn(conn_srv, buf, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(6, buf[4]);
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (buf + 5))));
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (buf + 9))));
    TEST_ASSERT_EQUAL(5, ntohl(*((uint32_t *) (buf + 13))));
    TEST_ASSERT_NOT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_EQUAL_MEMORY(bitfield + 5, peer.peer_bitfield, 1);
}

TEST(peer_proto, recv_bitfield_incomplete_unchoked_waiting)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0xe0 };

    peer.am_choking = 0;
    peer.waiting_piece = 1;
    client_init("incomplete_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL_MEMORY(bitfield + 5, peer.peer_bitfield, 1);
}

TEST(peer_proto, recv_bitfield_incomplete_reserved)
{
    unsigned char bitfield[2707] = { 0x00 };
    char buf[17];

    *((uint32_t *) bitfield) = htonl(2703);
    bitfield[4] = 5;
    *((uint32_t *) (bitfield + 17)) = 0x80;

    peer.am_choking = 0;
    peer.am_interested = 1;
    peer.reserved = 96;
    peer.received = 1002;
    peer.has_reserved = 1;
    client_init("not_existing");
    TEST_ASSERT_EQUAL(2707, writen(conn_srv, bitfield, 2707));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL_MEMORY(bitfield + 5, peer.peer_bitfield, 2702);

    TEST_ASSERT_EQUAL(17, readn(conn_srv, buf, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(6, buf[4]);
    TEST_ASSERT_EQUAL(96, ntohl(*((uint32_t *) (buf + 5))));
    TEST_ASSERT_EQUAL(1002, ntohl(*((uint32_t *) (buf + 9))));
    TEST_ASSERT_EQUAL(16384, ntohl(*((uint32_t *) (buf + 13))));
    TEST_ASSERT_NOT_EQUAL(0, peer.has_reserved);
}

TEST(peer_proto, recv_unchoke_complete)
{

    struct peer other = { .sockfd = conn_srv };

    peer.am_choking = 1;
    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_NOT_EQUAL(0, peer_send_unchoke(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0, peer.am_choking);
}

TEST(peer_proto, recv_unchoke_incomplete)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0xe0 };
    char buf[17];
    struct peer other = { .sockfd = conn_srv };

    peer.am_choking = 1;
    client_init("incomplete_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(2, buf[4]);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_NOT_EQUAL(0, peer_send_unchoke(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0, peer.am_choking);

    TEST_ASSERT_EQUAL(17, readn(conn_srv, buf, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(6, buf[4]);
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (buf + 5))));
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (buf + 9))));
    TEST_ASSERT_EQUAL(5, ntohl(*((uint32_t *) (buf + 13))));
}

TEST(peer_proto, recv_unchoke_full)
{
    unsigned char bitfield[2707] = { 0x00 };
    char buf[17];
    struct peer other = { .sockfd = conn_srv };

    *((uint32_t *) bitfield) = htonl(2703);
    bitfield[4] = 5;
    *((uint32_t *) (bitfield + 17)) = 0x80;

    peer.am_choking = 1;
    client_init("not_existing");
    TEST_ASSERT_EQUAL(2707, writen(conn_srv, bitfield, 2707));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(2, buf[4]);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_interested);

    TEST_ASSERT_NOT_EQUAL(0, peer_send_unchoke(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0, peer.am_choking);
    TEST_ASSERT_EQUAL(17, readn(conn_srv, buf, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(6, buf[4]);
    TEST_ASSERT_EQUAL(96, ntohl(*((uint32_t *) (buf + 5))));
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (buf + 9))));
    TEST_ASSERT_EQUAL(16384, ntohl(*((uint32_t *) (buf + 13))));
}

TEST(peer_proto, recv_unchoke_waiting)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0xe0 };
    char buf[17];
    struct peer other = { .sockfd = conn_srv };

    peer.waiting_piece = 1;
    client_init("incomplete_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(5, readn(conn_srv, buf, 5));
    TEST_ASSERT_EQUAL(1, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(2, buf[4]);
    TEST_ASSERT_NOT_EQUAL(0, peer.am_interested);
    TEST_ASSERT_NOT_EQUAL(0, peer_send_unchoke(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0, peer.am_choking);
}

TEST(peer_proto, recv_unchoke_reserved)
{
    unsigned char bitfield[2707] = { 0x00 };
    char buf[17];
    struct peer other = { .sockfd = conn_srv };

    *((uint32_t *) bitfield) = htonl(2703);
    bitfield[4] = 5;
    *((uint32_t *) (bitfield + 17)) = 0x80;

    peer.am_interested = 1;
    peer.reserved = 96;
    peer.received = 1002;
    peer.has_reserved = 1;
    client_init("not_existing");
    TEST_ASSERT_EQUAL(2707, writen(conn_srv, bitfield, 2707));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_NOT_EQUAL(0, peer_send_unchoke(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0, peer.am_choking);
    TEST_ASSERT_EQUAL(17, readn(conn_srv, buf, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) buf));
    TEST_ASSERT_EQUAL(6, buf[4]);
    TEST_ASSERT_EQUAL(96, ntohl(*((uint32_t *) (buf + 5))));
    TEST_ASSERT_EQUAL(1002, ntohl(*((uint32_t *) (buf + 9))));
    TEST_ASSERT_EQUAL(16384, ntohl(*((uint32_t *) (buf + 13))));
}

TEST(peer_proto, recv_interested)
{
    struct peer other = { .sockfd = conn_srv };

    TEST_ASSERT_NOT_EQUAL(0, peer_send_interested(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_NOT_EQUAL(0, peer.peer_interested);
}

TEST(peer_proto, recv_not_interested)
{
    struct peer other = { .sockfd = conn_srv };

    TEST_ASSERT_NOT_EQUAL(0, peer_send_not_interested(&other));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0, peer.peer_interested);
}

TEST(peer_proto, recv_have)
{
    char bitfield[] = { 0x00, 0x00, 0x00, 0x02, 0x05, 0x80 };
    char have[] = { 0x00, 0x00, 0x00, 0x05, 0x04, 0x00, 0x00, 0x00, 0x02 };

    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_EQUAL(6, writen(conn_srv, bitfield, 6));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0b10000000, peer.peer_bitfield[0]);
    TEST_ASSERT_EQUAL(9, writen(conn_srv, have, 9));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(0b10100000, peer.peer_bitfield[0]);
}

TEST(peer_proto, recv_request)
{
    struct peer other = { .sockfd = conn_srv };
    char piece[18];
    char expected[5] = { 0x74, 0xfb, 0xb3, 0x0b, 0x6d };

    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_NOT_EQUAL(0, peer_send_request(&other, 1, 0, 5));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(18, readn(conn_srv, piece, 18));

    TEST_ASSERT_EQUAL(14, ntohl(*(uint32_t *) piece));
    TEST_ASSERT_EQUAL(7, piece[4]);
    TEST_ASSERT_EQUAL(1, ntohl(*((uint32_t *) (piece + 5))));
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (piece + 9))));
    TEST_ASSERT_EQUAL_MEMORY(expected, piece + 13, 5);
    TEST_ASSERT_EQUAL(5, client_uploaded(peer.client));
}

TEST(peer_proto, recv_request_smaller_len)
{
    struct peer other = { .sockfd = conn_srv };
    char piece[18];
    char expected[2] = { 0x00, 0x13 };

    client_init("existing_file_len_non_multiple");
    TEST_ASSERT_NOT_EQUAL(0, peer_send_request(&other, 0, 1, 2));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_EQUAL(15, readn(conn_srv, piece, 15));

    TEST_ASSERT_EQUAL(11, ntohl(*(uint32_t *) piece));
    TEST_ASSERT_EQUAL(7, piece[4]);
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (piece + 5))));
    TEST_ASSERT_EQUAL(1, ntohl(*((uint32_t *) (piece + 9))));
    TEST_ASSERT_EQUAL_MEMORY(expected, piece + 13, 2);
    TEST_ASSERT_EQUAL(2, client_uploaded(peer.client));
}

TEST(peer_proto, recv_valid_piece)
{
    unsigned char buf[18] = {
	0x00, 0x00, 0x00, 0x0e,
	0x07,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0xd7, 0x00, 0x13, 0x10, 0x81
    };
    unsigned char res[17];
    FILE *fp;
    
    peer.waiting_piece = 1;
    peer.am_choking = 0;
    peer.am_interested = 1;
    peer.has_reserved = 1;
    peer.reserved = 0;
    peer.received = 0;
    client_init("piece_requests");
    peer.peer_bitfield[0] = 0xe0;

    TEST_ASSERT_EQUAL(18, writen(conn_srv, buf, 18));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_NOT_EQUAL(0, peer.waiting_piece);
    TEST_ASSERT_EQUAL(0, peer.received);
    TEST_ASSERT_NOT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_EQUAL(2, peer.reserved);

    TEST_ASSERT_EQUAL(9, readn(conn_srv, res, 9));
    TEST_ASSERT_EQUAL(5, ntohl(*(uint32_t *) res));
    TEST_ASSERT_EQUAL(4, res[4]);
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (res + 5))));

    TEST_ASSERT_EQUAL(17, readn(conn_srv, res, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) res));
    TEST_ASSERT_EQUAL(6, res[4]);
    TEST_ASSERT_EQUAL(2, ntohl(*((uint32_t *) (res + 5))));
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (res + 9))));
    TEST_ASSERT_EQUAL(3, ntohl(*((uint32_t *) (res + 13))));

    TEST_ASSERT_EQUAL(10, client_downloaded(peer.client));
    TEST_ASSERT_EQUAL(3, client_left(peer.client));

    client_free(peer.client);
    peer.client = NULL;

    fp = fopen("piece_requests", "rb");
    TEST_ASSERT_NOT_NULL(fp);
    TEST_ASSERT_EQUAL(5, fread(res, 1, 5, fp));
    fclose(fp);
    TEST_ASSERT_EQUAL_MEMORY(buf + 13, res, 5);
}


TEST(peer_proto, recv_invalid_piece)
{
    unsigned char buf[18] = {
	0x00, 0x00, 0x00, 0x0e,
	0x07,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0xd7, 0x00, 0x15, 0x10, 0x81
    };
    unsigned char res[17];
    FILE *fp;
    
    peer.waiting_piece = 1;
    peer.am_choking = 0;
    peer.am_interested = 1;
    peer.has_reserved = 1;
    peer.reserved = 0;
    peer.received = 0;
    client_init("piece_requests");
    peer.peer_bitfield[0] = 0xe0;

    TEST_ASSERT_EQUAL(18, writen(conn_srv, buf, 18));
    TEST_ASSERT_GREATER_THAN(0, peer_handle_msg(&peer));
    TEST_ASSERT_NOT_EQUAL(0, peer.waiting_piece);
    TEST_ASSERT_EQUAL(0, peer.received);
    TEST_ASSERT_NOT_EQUAL(0, peer.has_reserved);
    TEST_ASSERT_EQUAL(0, peer.reserved);

    TEST_ASSERT_EQUAL(17, readn(conn_srv, res, 17));
    TEST_ASSERT_EQUAL(13, ntohl(*(uint32_t *) res));
    TEST_ASSERT_EQUAL(6, res[4]);
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (res + 5))));
    TEST_ASSERT_EQUAL(0, ntohl(*((uint32_t *) (res + 9))));
    TEST_ASSERT_EQUAL(5, ntohl(*((uint32_t *) (res + 13))));

    TEST_ASSERT_EQUAL(5, client_downloaded(peer.client));
    TEST_ASSERT_EQUAL(8, client_left(peer.client));

    client_free(peer.client);
    peer.client = NULL;

    fp = fopen("piece_requests", "rb");
    TEST_ASSERT_NOT_NULL(fp);
    TEST_ASSERT_EQUAL(5, fread(res, 1, 5, fp));
    fclose(fp);
    memset(buf, 0x00, 5);
    TEST_ASSERT_EQUAL_MEMORY(buf, res, 5);
}


TEST_GROUP_RUNNER(peer_proto)
{
    RUN_TEST_CASE(peer_proto, send_choke);
    RUN_TEST_CASE(peer_proto, send_unchoke);
    RUN_TEST_CASE(peer_proto, send_interested);
    RUN_TEST_CASE(peer_proto, send_not_interested);
    RUN_TEST_CASE(peer_proto, send_have);
    RUN_TEST_CASE(peer_proto, send_bitfield_complete);
    RUN_TEST_CASE(peer_proto, send_bitfield_empty);
    RUN_TEST_CASE(peer_proto, send_bitfield_incomplete);
    RUN_TEST_CASE(peer_proto, send_request);
    RUN_TEST_CASE(peer_proto, send_piece);

    RUN_TEST_CASE(peer_proto, recv_choke);
    RUN_TEST_CASE(peer_proto, recv_keepalive);
    RUN_TEST_CASE(peer_proto, recv_interested);
    RUN_TEST_CASE(peer_proto, recv_not_interested);
    RUN_TEST_CASE(peer_proto, recv_have);
    RUN_TEST_CASE(peer_proto, recv_request);
    RUN_TEST_CASE(peer_proto, recv_request_smaller_len);

    RUN_TEST_CASE(peer_proto, recv_bitfield_complete_choked);
    RUN_TEST_CASE(peer_proto, recv_bitfield_complete_unchoked);
    RUN_TEST_CASE(peer_proto, recv_bitfield_incomplete_choked);
    RUN_TEST_CASE(peer_proto, recv_bitfield_incomplete_unchoked);
    RUN_TEST_CASE(peer_proto, recv_bitfield_incomplete_unchoked_waiting);
    RUN_TEST_CASE(peer_proto, recv_bitfield_incomplete_reserved);

    RUN_TEST_CASE(peer_proto, recv_unchoke_complete);
    RUN_TEST_CASE(peer_proto, recv_unchoke_incomplete);
    RUN_TEST_CASE(peer_proto, recv_unchoke_full);
    RUN_TEST_CASE(peer_proto, recv_unchoke_reserved);
    RUN_TEST_CASE(peer_proto, recv_unchoke_waiting);

    RUN_TEST_CASE(peer_proto, recv_valid_piece);
    RUN_TEST_CASE(peer_proto, recv_invalid_piece);
}
