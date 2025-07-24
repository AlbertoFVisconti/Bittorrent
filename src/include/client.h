#ifndef CLIENT_H_INCLUDED
#define CLIENT_H_INCLUDED

#include <bencode.h>
#include <metainfo.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <peer.h>

#define MAX_PEERS 20;

struct client {
    unsigned char *bitfield;
    unsigned char *reserved; // The set of reserved pieces

    int bitfield_len;
    // TODO fill with other fields from assignment 2
    //basic info about the client
    unsigned char peer_id[20];
    size_t uploaded;
    size_t downloaded;
    size_t missing;
    struct metainfo_file* torrent;
    uint16_t port;

    //peers recived by the tracker 
    struct peer *peers;
    size_t num_peers;

    //peers that connect to the peer listener 
    struct peer **new_peers;
    size_t num_new_peers;
    struct peer_listener *listener;

    //thread that periodically sends data to the tracker
    struct tracker_connection *tracker_connection; 
    char* download_status;

    //threads to manage connection with the clients
    pthread_t pool[20];
    int thread_status[20];

    //lock to avoid data races
    pthread_mutex_t bitfield_lock;
    pthread_mutex_t reserved_lock;
    pthread_mutex_t file_lock;
};

struct client *client_new(const struct metainfo_file *torrent, uint16_t port);
void client_free(struct client *client);


const unsigned char *client_peer_id(struct client *client);
uint16_t client_port(struct client *client);
size_t client_uploaded(struct client *client);
size_t client_downloaded(struct client *client);
size_t client_left(struct client *client);
const struct metainfo_file *client_torrent(struct client *client);

int client_tracker_connect(struct client *client);
int client_peer_listener_start(struct client *client);

void client_add_connected_peer(struct client *client, int sockfd);
void client_add_bencoded_peer_list(struct client *client, const struct bencode_value *peers);

void client_bitfield(struct client *client, unsigned char *buf);
int client_reserve_piece(struct client *client, unsigned char *bitfield, uint32_t *piece);
void client_unreserve_piece(struct client *client, uint32_t piece);
void bitfield_set(unsigned char *bitfield, size_t i);
int bitfield_is_set(unsigned char *bitfield, size_t i);

int client_read_request(struct client *client, void *buf, size_t piece, size_t offset, size_t len);
int client_write_piece(struct client *client, void *buf, size_t piece);

#endif
