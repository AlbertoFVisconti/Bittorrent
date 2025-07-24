#ifndef PEER_H_INCLUDED
#define PEER_H_INCLUDED

#include <pthread.h>
#include <bencode.h>
#include <stddef.h>
#include <stdint.h>

struct client;

enum peer_msg_t {
    MSG_CHOKE = 0,
    MSG_UNCHOKE = 1,
    MSG_INTERESTED = 2,
    MSG_NOT_INTERESTED = 3,
    MSG_HAVE = 4,
    MSG_BITFIELD = 5,
    MSG_REQUEST = 6,
    MSG_PIECE = 7,
};

struct peer {
    struct client *client;
    unsigned char peer_id[20];
    int sockfd;
    unsigned char *peer_bitfield;
    unsigned char *piece;
    size_t received;
    uint32_t reserved;
    int has_reserved;
    int waiting_piece;
    int am_choking;
    int am_interested;
    int peer_choking;
    int peer_interested;
};

int peer_init(struct peer *peer, struct client *client, int sockfd);
int peer_connect(struct peer *peer, struct client *client,
		 const char *ip, uint16_t port);
void peer_free(struct peer *peer);


int peer_handle_msg(struct peer *peer);
int peer_send_choke(struct peer *peer);
int peer_send_unchoke(struct peer *peer);
int peer_send_interested(struct peer *peer);
int peer_send_not_interested(struct peer *peer);
int peer_send_have(struct peer *peer, uint32_t index);
int peer_send_bitfield(struct peer *peer);
int peer_send_request(struct peer *peer, uint32_t index, uint32_t begin, uint32_t length);
int peer_send_piece(struct peer *peer, uint32_t index, uint32_t begin, uint32_t length);

#endif
