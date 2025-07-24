#include <peer.h>
#include <client.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>  /* For struct sockaddr, socket, accept, listen, bind */
#include <netinet/in.h>  /* For struct sockaddr_in */
#include <arpa/inet.h>   /* For htons, htonl, inet_pton */
#include <errno.h>       /* For errno */
#include <stdint.h>
#include <unistd.h>      /* For close, read, write */
#include <arpa/inet.h>
#include <netdb.h> // per getaddrinfo
#include <sys/time.h>

#define PROTOCOL_STRING "BitTorrent protocol"
#define PROTOCOL_LEN 68

struct tracker_connection{
    long long interval;//how long to wait between requests
    pthread_t thread;

};
/*
helped by Pasquale to improve peer_connect
resources used:
https://www.geeksforgeeks.org/memset-c-example/
https://www.geeksforgeeks.org/input-output-system-calls-c-create-open-close-read-write/
https://www.inf.usi.ch/carzaniga/edu/adv-ntw/tcp_client.c
https://www.inf.usi.ch/carzaniga/edu/adv-ntw/socket_programming.html
*/
int peer_init(struct peer *peer, struct client *client, int sockfd)
{
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // Set read and write timeouts
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    unsigned char message[PROTOCOL_LEN]; // 1  + 19 + 8 (bunch of 0) + 20 (info hash) + 20 (peer ID)
    int pos=0;
    message[pos]=19;
    pos++;

    memcpy(message+pos,PROTOCOL_STRING,strlen(PROTOCOL_STRING));
    pos+=strlen(PROTOCOL_STRING);

    memset(message+pos, 0,8 );
    pos+=8;

    memcpy(message+pos, client->torrent->info_hash,20 );
    pos+=20;

    memcpy(message+pos,client->peer_id,20);
    pos+=20;

    size_t written = 0;
    while (written < PROTOCOL_LEN) {
	/* write to the socket object */
	ssize_t w_res = write(sockfd, message + written, PROTOCOL_LEN - written);
	if (w_res < 0) {
	    close(sockfd);
	    return 0;
	}
	written += w_res;
    }

    unsigned char response[PROTOCOL_LEN];
    if(read(sockfd, response, PROTOCOL_LEN)!=PROTOCOL_LEN){
        return 0; 
    }

    if(response[0]!=19 || (memcmp(response+1,PROTOCOL_STRING,strlen(PROTOCOL_STRING))!=0)
    || (memcmp(response+1+strlen(PROTOCOL_STRING),message+1+strlen(PROTOCOL_STRING),8))
    || (memcmp(response+1+strlen(PROTOCOL_STRING)+8,client->torrent->info_hash,20)!=0)
    ){
        return 0;
    }

    //fill the peer info
    pos=1+strlen(PROTOCOL_STRING)+8+20;
    memcpy(peer->peer_id,response+pos, 20);
    peer->client=client;
    peer->peer_bitfield=malloc(client->bitfield_len*sizeof(unsigned char));
    memset(peer->peer_bitfield,0,client->bitfield_len*sizeof(unsigned char));
    peer->piece=malloc(client->torrent->info.piece_length*sizeof(unsigned char));
    memset(peer->piece,0,client->torrent->info.piece_length*sizeof(unsigned char));
    peer->has_reserved=0;
    peer->am_choking=1;
    peer->peer_choking=1;
    peer->am_interested=0;
    peer->peer_interested=0;

    return 1;
}


int peer_connect(struct peer *peer, struct client *client, const char *ip, uint16_t port)
{
    peer->sockfd = -1;

    struct addrinfo hints, *res, *p;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(ip, port_str, &hints, &res);
    if (rc != 0) {
        return 0;
    }

    for (p = res; p; p = p->ai_next) {
        int conn = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (conn < 0) continue;

        if (connect(conn, p->ai_addr, p->ai_addrlen) == 0) {
            freeaddrinfo(res);
            if (peer_init(peer, client, conn) == 0) {
                close(conn);
                return 0;
            }
            peer->sockfd = conn;
            return 1;
        }

        close(conn);
    }

    freeaddrinfo(res);
    return 0;
}

void peer_free(struct peer *peer)
{
    if(peer->sockfd>0){
        shutdown(peer->sockfd, SHUT_RDWR);
        close(peer->sockfd);
    }
}

// some helper functions you might need in peer_handle_msg
#define BLOCK_SIZE 16384
__attribute__((unused))
static int peer_request_piece(struct peer *peer)
{
    if(1==peer->waiting_piece){
        return 1;
    }
    uint32_t i=0;
    if(1==peer->has_reserved){
        if(0!=metainfo_file_piece_len(peer->client->torrent, peer->reserved)/BLOCK_SIZE){
            for(i=0;i<metainfo_file_piece_len(peer->client->torrent, peer->reserved)/BLOCK_SIZE;i++){
                peer_send_request(peer,peer->reserved,peer->received,BLOCK_SIZE);
            }
        }
        if(0!=metainfo_file_piece_len(peer->client->torrent, peer->reserved)-i*BLOCK_SIZE){
            peer_send_request(peer,peer->reserved,peer->received,metainfo_file_piece_len(peer->client->torrent, peer->reserved));
        }
    }

    
    uint32_t *piece=malloc(sizeof(uint32_t));
    if(1==client_reserve_piece(peer->client,peer->peer_bitfield,piece)){
        peer->has_reserved=1;
        peer->reserved=*piece;
    }

    if(0==peer->am_interested){
        peer_send_interested(peer);
    }

    u_int32_t remaining=remaining=(metainfo_file_piece_len(peer->client->torrent,peer->reserved)<BLOCK_SIZE)?
    metainfo_file_piece_len(peer->client->torrent,peer->reserved):BLOCK_SIZE;
    peer_send_request(peer,(peer->has_reserved==1)?peer->reserved:0,i*BLOCK_SIZE,remaining);
    return 1;
}

__attribute__((unused))
static int peer_handle_unchoke(struct peer *peer)
{
    peer->am_choking=0;
    return peer_request_piece(peer);
}

__attribute__((unused))
static int peer_handle_bitfield(struct peer *peer, uint32_t len)
{
    unsigned char buffer[len];
	read(peer->sockfd, buffer, len);
    if(NULL==peer->peer_bitfield){
        peer->peer_bitfield=malloc(len*sizeof(unsigned char));
    }
    
    memcpy(peer->peer_bitfield,buffer,len);


    if(0==peer->am_choking){
        peer_request_piece(peer);
    }

    if(0==peer->am_interested){
        int i=0;
        for(i=0;i<len*8;i++){
            if(0==bitfield_is_set(peer->client->bitfield,i)){
                peer_send_interested(peer);
                return 1;
            }
        }
    }
    
    return 1;
}

__attribute__((unused))
static int peer_handle_request(struct peer *peer)
{
    //receive and decode the request from the peer
    uint8_t header[12]; //4 index+ 4 offset +4 len 
    if(read(peer->sockfd,header,12)!=12){
        return 0;
    }
    uint32_t index,offset,len;
    memcpy(&index,header,4);
    memcpy(&offset,header+4,4);
    memcpy(&len,header+8,4);
    index=ntohl(index);
    offset=ntohl(offset);
    len=ntohl(len);
    // send the requested piece
    return peer_send_piece(peer,index,offset,len);
}

__attribute__((unused))
static int peer_handle_piece(struct peer *peer, uint32_t len)
{
    if(0==peer->waiting_piece){
        return 0;
    }    
    peer->waiting_piece=0;
    uint8_t header[8]; // 4 index + 4 begin
    if (read(peer->sockfd, header, 8) != 8) {
        return 0; 
    }
    uint32_t index, begin;
    memcpy(&index, header, 4);
    memcpy(&begin, header + 4, 4);
    index = ntohl(index);
    begin = ntohl(begin);
    uint32_t piece_size = len - 8;


    uint8_t *piece_data = malloc(piece_size);
    ssize_t readi= read(peer->sockfd,piece_data,piece_size);
    if(readi<0){
        return 0;
    }


    if(1==metainfo_file_verify(peer->client->torrent,piece_data,piece_size,index)){
        client_write_piece(peer->client, piece_data,index);
        peer->client->downloaded+=readi;
        peer->client->missing-=readi;
        peer->has_reserved=0;
        peer_send_have(peer,index);
        
    }
    else{
        client_unreserve_piece(peer->client,index);
    }
    peer_request_piece(peer);
    return 1;
}

int peer_handle_msg(struct peer *peer)
{

    // read the message length
    uint8_t header[4]; //4 len
    if(read(peer->sockfd,header,4)!=4){
        return 0;
    }
    uint32_t msg_len;
    memcpy(&msg_len,header,4);
    msg_len=ntohl(msg_len);
    // if it is a keep alive return
    if(0==msg_len){
        return 1;
    }
    // read the message type
    uint8_t msg_type;
    if(read(peer->sockfd,&msg_type,1)!=1){
        return 0;
    }
    msg_type=msg_type;
    switch (msg_type)
    {
        case MSG_CHOKE:{
            peer->am_choking=1;
            return 1;
        }
        case MSG_UNCHOKE:{
            return peer_handle_unchoke(peer);
        }
        case MSG_INTERESTED:{
            peer->peer_interested=1;
            return 1;
        }
        case MSG_NOT_INTERESTED:{
            peer->peer_interested=0;
            return 1;
        }
        case MSG_HAVE:{
            uint8_t index[4]; //4 len
            if(read(peer->sockfd,index,4)!=4){
                return 0;
            }
            uint32_t have;
            memcpy(&have,index,4);
            have=ntohl(have);
            bitfield_set(peer->peer_bitfield,have);
            return 1;
        }
        case MSG_BITFIELD:{
            return peer_handle_bitfield(peer,msg_len-1);
            
        }
        case MSG_REQUEST:{
            return peer_handle_request(peer);
        }
        case MSG_PIECE:{
            return peer_handle_piece(peer,msg_len-1);
        }
        default:
            break;
    }


    return 1;
}

int peer_send_choke(struct peer *peer)
{
    //  send the total message length in network order
    uint32_t length=htonl(1);
    if (write(peer->sockfd, &length, sizeof(length)) != sizeof(length)){
        return 0;
    }
    //  send a byte with value MSG_CHOKE
    uint8_t id=MSG_CHOKE;
    if (write(peer->sockfd, &id, sizeof(id)) != sizeof(id)){
        return 0;
    }
    //  set the correct field in peer
    peer->am_choking=1;
    return 1;
}

int peer_send_unchoke(struct peer *peer)
{
    //  send the total message length in network order
    uint32_t length=htonl(1);
    if (write(peer->sockfd, &length, sizeof(length)) != sizeof(length)){
        return 0;
    }
    //  send a byte with value MSG_UNCHOKE
    uint8_t id=MSG_UNCHOKE;
    if (write(peer->sockfd, &id, sizeof(id)) != sizeof(id)){
        return 0;
    }
    //  set the correct field in peer
    peer->peer_choking=0;
    return 1;
}

int peer_send_interested(struct peer *peer)
{
    //  send the total message length in network order
    uint32_t length=htonl(1);
    if (write(peer->sockfd, &length, sizeof(length)) != sizeof(length)){
        return 0;
    }
    //  send a byte with value MSG_INTERESTED
    uint8_t id=MSG_INTERESTED;
    if (write(peer->sockfd, &id, sizeof(id)) != sizeof(id)){
        return 0;
    }
    //  set the correct field in peer
    peer->am_interested=1;
    return 1;
}

int peer_send_not_interested(struct peer *peer)
{
    //  send the total message length in network order
    uint32_t length=htonl(1);
    if (write(peer->sockfd, &length, sizeof(length)) != sizeof(length)){
        return 0;
    }
    // send a byte with value MSG_NOT_INTERESTED
    uint8_t id=MSG_NOT_INTERESTED;
    if (write(peer->sockfd, &id, sizeof(id)) != sizeof(id)){
        return 0;
    }
    // set the correct field in peer
    peer->am_interested=0;
    return 1; 
}

int peer_send_have(struct peer *peer, uint32_t index)
{
    // send the total message length in network order
    uint32_t length=htonl(1+4); // 1 id+ 4 index
    if (write(peer->sockfd, &length, sizeof(length)) != sizeof(length)){
        return 0;
    }
    // send a byte with value MSG_HAVE
    uint8_t id=MSG_HAVE;
    if (write(peer->sockfd, &id, sizeof(id)) != sizeof(id)){
        return 0;
    }
    // send index in network order
    uint32_t net_index=htonl(index);
    if (write(peer->sockfd, &net_index, sizeof(net_index)) != sizeof(net_index)){
        return 0;
    }

    return 1;
}
    
int peer_send_bitfield(struct peer *peer)
{
    // get the bitfield from the client
    unsigned char * bf= malloc(peer->client->bitfield_len*sizeof(unsigned char));
    client_bitfield(peer->client, bf);
    if(NULL==bf){
        return 0;
    }
    // send the total message length in network order
    // send a byte with value MSG_BITFIELD
    // send the bitfield
    int message_len = 1+ peer->client->bitfield_len;
    uint32_t nw_ml= htonl(message_len);

    uint8_t *message = malloc(4 + message_len);
    if (!message) return 0;

    memcpy(message, &nw_ml, 4); 
    message[4] = MSG_BITFIELD; 
    
    memcpy(message + 5, bf, peer->client->bitfield_len); 

    if(write(peer->sockfd, message, 4 + message_len)!=(4+message_len)){
        return 0;
    }
    free(message);
    return 1;
}

int peer_send_request(struct peer *peer, uint32_t index, uint32_t begin, uint32_t length)
{
    uint8_t buffer[17]; //4 total_len_msg + 1 id + 4 index + 4 begin + 4 length
    // send the total message length in network order
    uint32_t msg_length = htonl(13);  
    memcpy(buffer, &msg_length, 4);
    // send a byte with value MSG_REQUEST
    buffer[4] = MSG_REQUEST;
    // send index in network order
    uint32_t net_index = htonl(index);
    memcpy(buffer + 5, &net_index, 4);
    // send begin in network order
    uint32_t net_begin = htonl(begin);
    memcpy(buffer + 9, &net_begin, 4);
    // send length in network order
    uint32_t net_length = htonl(length);
    memcpy(buffer + 13, &net_length, 4);

    if (write(peer->sockfd, buffer, 17) != 17) {
        return 0;
    }
    // set peer->waiting_piece to 1
    peer->waiting_piece = 1;

    return 1;
}

int peer_send_piece(struct peer *peer, uint32_t index, uint32_t begin, uint32_t length)
{
    // send the total message length in network order
    uint32_t msg_len=htonl(1+4+4+length);
    if (write(peer->sockfd, &msg_len, sizeof(msg_len)) != sizeof(msg_len)){
        return 0;
    }
    // send a byte with value MSG_PIECE
    uint8_t id=MSG_PIECE;
    if (write(peer->sockfd, &id, sizeof(id)) != sizeof(id)){
        return 0;
    }
    // send index in network order
    uint32_t nw_index=htonl(index);
    if (write(peer->sockfd, &nw_index, sizeof(nw_index)) != sizeof(nw_index)){
        return 0;
    }
    // send begin in network order
    uint32_t nw_begin=htonl(begin);
    if (write(peer->sockfd, &nw_begin, sizeof(nw_begin)) != sizeof(nw_begin)){
        return 0;
    }
    // read the piece from the file and write it into peer->sockfd.
    unsigned char *buf=malloc(length*sizeof(unsigned char));
    client_read_request(peer->client,buf,index,begin,length);
    size_t written = 0;
    while (written < length) {
        /* write to the socket object */
        ssize_t w_res = write(peer->sockfd, buf + written, length - written);
        if (w_res < 0) {
            return 0;
        }
        written += w_res;
    }
    return 1;
}
