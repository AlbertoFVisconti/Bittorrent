#include <client.h>
#include <tracker_connection.h>
#include <bencode.h>
#include <peer_listener.h>

// Include this header file to use the RAND_bytes
// function.
#include <openssl/rand.h>
// Include this header file to use the encryption/decryption API.
#include <openssl/evp.h>
// Include this header file to do error handling.
#include <openssl/err.h>
#include <string.h>
#include <sys/socket.h>  /* For struct sockaddr, socket, accept, listen, bind */
#include <netinet/in.h>  /* For struct sockaddr_in */
#include <arpa/inet.h>   /* For htons, htonl, inet_pton */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>       /* For errno */
#include <stdint.h>
#include <unistd.h>      /* For close, read, write */
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <curl/curl.h>

struct tracker_connection{
    long long interval;//how long to wait between requests
    pthread_t thread;

};

struct client *client_new(const struct metainfo_file *torrent, uint16_t port)
{
    struct client *client = malloc(sizeof(struct client));
    //initialize the info 
    RAND_bytes(client->peer_id, sizeof(client->peer_id));
    client->downloaded = 0;
    client->missing=torrent->info.length;
    client->uploaded=0;
    client->port = port;
    client->torrent= (struct metainfo_file *) torrent;

    //initialize the peers 
    client->peers=NULL;
    client->num_peers=0;
    client->new_peers=NULL;
    memset(client->thread_status,0,20*sizeof(int));
    client->listener=NULL;
    client->num_new_peers=0;
    client->tracker_connection=NULL;
    client->download_status=NULL;

    size_t bf_len= (metainfo_file_pieces_count(client->torrent)+7)/8;
    client->bitfield_len=bf_len;
    client->bitfield=malloc(bf_len*sizeof(unsigned char));
    memset(client->bitfield,0,bf_len*sizeof(unsigned char));

    client->reserved=malloc(bf_len*sizeof(unsigned char));
    memset(client->reserved,0,bf_len*sizeof(unsigned char));

    pthread_mutex_init(&client->bitfield_lock,NULL);
    pthread_mutex_init(&client->reserved_lock,NULL);
    pthread_mutex_init(&client->file_lock,NULL);


    FILE* file=fopen(torrent->info.name,"rb");
    if (NULL==file) {
        //create file if it does not exist
        file=fopen(torrent->info.name,"wb");
        fclose(file);
        return client;
    }
    
    fseek(file, 0L, SEEK_END);
    long local_file_len = ftell(file);
    fseek(file, 0L, SEEK_SET);

    if(0==local_file_len){
        return client;
    }

    int i=0;
    for(i=0; i< metainfo_file_pieces_count(torrent) && (i+1)*torrent->info.piece_length<=local_file_len;i++){
        unsigned char data[torrent->info.piece_length];
        fread(data, sizeof(char), torrent->info.piece_length, file);
        unsigned char digest[20];

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            fclose(file);
            return 0;
        }

        if(EVP_DigestInit(ctx, EVP_sha1()) != 1
            || EVP_DigestUpdate(ctx, data, torrent->info.piece_length) != 1
            || EVP_DigestFinal(ctx, digest, NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return 0;
        }

        EVP_MD_CTX_free(ctx);

        if (0==memcmp(digest, metainfo_file_piece_hash(torrent,i),20)) {
            client->downloaded+=torrent->info.piece_length;
            client->missing-=torrent->info.piece_length;
            bitfield_set(client->bitfield,i);
        }

    }

    size_t remaining= local_file_len-(i)*torrent->info.piece_length;
    if(0==remaining){
        fclose(file);
        return client;
    }
    unsigned char data[remaining];
    fread(data, sizeof(char), remaining, file);
    unsigned char digest[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return 0;        
    }

    if(EVP_DigestInit(ctx, EVP_sha1()) != 1
        || EVP_DigestUpdate(ctx, data, remaining) != 1
        || EVP_DigestFinal(ctx, digest, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return 0;
    }
    EVP_MD_CTX_free(ctx);

    if (0==memcmp(digest, metainfo_file_piece_hash(torrent,i),20)) {
        client->downloaded+=remaining;
        client->missing-=remaining;
        bitfield_set(client->bitfield,i);
    }
    fclose(file);
    return client;
}
typedef struct
{
  char *string;
  size_t size;
} Response;
size_t write_chunk_url(void *data, size_t size, size_t nmemb, void *userdata)
{
  size_t real_size = size * nmemb; 
  Response *response = (Response *) userdata; 
  char *ptr = realloc(response->string, response->size + real_size + 1);
  if (ptr == NULL)
  {
    return CURL_WRITEFUNC_ERROR;  
  }
  response->string = ptr;
  memcpy(&(response->string[response->size]), data, real_size);
  response->size += real_size;
  response->string[response->size] = 0;
  return real_size;
}
void client_free(struct client *client)
{
peer_listener_free(client->listener);
    int i=0;
    for(i=0;i<client->num_peers;i++){
        peer_free(&client->peers[i]);
    }
    if(client->num_peers>0){
        free(client->peers);
    }
    for(i=0;i<client->num_new_peers;i++){
        peer_free(client->new_peers[i]);
        free(client->new_peers[i]);
    }
    if(client->tracker_connection!=NULL){
        CURL *curl;
        curl = curl_easy_init();
        if (curl == NULL)
        {
            return;
        }
        Response response;
        response.string = malloc(1); 
        response.size = 0;
        char url[2048];
        char *info_hash_safe=curl_easy_escape(curl,(char *)client->torrent->info_hash,20);
        char *peer_id_safe=curl_easy_escape(curl,(char *)client->peer_id,20);
        char event[]="stopped";
        sprintf(url, "%s?info_hash=%s&peer_id=%s&port=%hu&uploaded=%zu&downloaded=%zu&left=%zu&event=%s",
        client->torrent->announce,info_hash_safe,peer_id_safe,client->port,client->uploaded,client->downloaded, client->missing,event);
        curl_easy_setopt(curl, CURLOPT_URL, url); 
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_chunk_url); 
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
        curl_easy_setopt(curl,CURLOPT_TIMEOUT,20);
        curl_easy_perform(curl);
        tracker_connection_free(client->tracker_connection);
    }
    memset(client->peer_id,0,20);
    memset(client->torrent->info_hash,0,20);
    client->num_peers=0;
}

const unsigned char *client_peer_id(struct client *client)
{
    return client->peer_id;
}

uint16_t client_port(struct client *client)
{
    return client->port;
}

size_t client_uploaded(struct client *client)
{
    return client->uploaded;
}

size_t client_downloaded(struct client *client)
{
    return client->downloaded;
}

size_t client_left(struct client *client)
{
   return client->missing;
}

const struct metainfo_file *client_torrent(struct client *client)
{
   return client->torrent;
}

pthread_t thread;
long long interval=0;

struct tracker_thread_args {
    struct client *client;
    long long interval;
    pthread_barrier_t barrier;
};

void *tracker_thread_loop(void *arg) {
    struct tracker_thread_args *args = (struct tracker_thread_args *)arg;
    struct client *client = args->client;
    long long interval = args->interval;
    int status_sent=0;

    // Signal that the thread is ready before entering the loop
    pthread_barrier_wait(&args->barrier);
    pthread_barrier_destroy(&args->barrier);

    free(args);

    for (;;) {
        sleep(interval);
        if(0==client->missing&&0==status_sent){
            client->download_status="completed";
            status_sent=1;
        }
        else{
            client->download_status="";
        }
        tracker_connection_new(client);
    }
    return NULL;
}
int client_tracker_connect(struct client *client)
{
    client->download_status="started";
    struct tracker_connection *temp = tracker_connection_new(client);
    client->tracker_connection=temp;
    
    if (NULL == temp) {
        return 0;
    }
    if(-123==temp->interval){
        return 1;
    }
    // Allocate memory for thread args
    struct tracker_thread_args *args = malloc(sizeof(struct tracker_thread_args));
    if (!args) {
        return 0;
    }
    args->client = client;
    args->interval = temp->interval;

    // Initialize barrier
    if (pthread_barrier_init(&args->barrier, NULL, 2) != 0) {
        free(args);
        return 0;
    }

    // Create the tracker thread
    if (pthread_create(&temp->thread, NULL, tracker_thread_loop, (void *)args) != 0) {
        pthread_barrier_destroy(&args->barrier);
        free(args);
        return 0;
    }

    // Wait until the tracker thread signals that it's ready
    pthread_barrier_wait(&args->barrier);

    return 1;
}

int client_peer_listener_start(struct client *client)
{
    if(NULL==peer_listener_new(client)){
        return 0;
    }
    return 1;
}

void *peer_thread(void *arg) {
    struct peer *peer = (struct peer *)arg;
    while (1) {
        if (!peer_handle_msg(peer)) {
            break;
        }
    }
    return NULL;
}

void client_add_connected_peer(struct client *client, int sockfd)
{
if(NULL==client|| sockfd<0){
        return;
    }
    struct peer *new_peer=malloc(sizeof(struct peer));
    memset(new_peer->peer_id,0,20);
    new_peer->sockfd=-1;
    if(1==peer_init(new_peer,client,sockfd)){
        struct peer **new_peer_list=malloc((client->num_new_peers+1)*sizeof(struct peer*));
        int i=0;
        for(i=0; i<client->num_new_peers;i++){
            new_peer_list[i]=client->new_peers[i];
        }
        new_peer_list[i]=new_peer;
        client->num_new_peers++;
        free(client->new_peers);
        client->new_peers=new_peer_list;
        pthread_create(&thread, NULL, peer_thread, &new_peer);
    }else{
        free(new_peer);
    }
}


void client_add_bencoded_peer_list(struct client *client, const struct bencode_value *peers)
{
 client->num_peers=bencode_value_len(peers);
    client->peers=malloc(client->num_peers*sizeof(struct peer));
    for(size_t i=0;i<client->num_peers;i++){
        const struct bencode_value *value=bencode_list_get(peers,i);
        if(NULL==bencode_map_lookup(value,"peer id")||NULL==bencode_map_lookup(value,"ip")||NULL==bencode_map_lookup(value,"port"))
        {
            return;
        }
        int len=bencode_map_lookup(value,"ip")->value.stringlen;
        memcpy(client->peers[i].peer_id, bencode_map_lookup(value, "peer id")->value.string, 20);
        char *ip=malloc((len+1)*sizeof(unsigned char));
        
        memcpy(ip,bencode_map_lookup(value,"ip")->value.string,len);
        ip[len]='\0';
        uint16_t port=(uint16_t)bencode_map_lookup(value,"port")->value.number;
        peer_connect(&client->peers[i],client,ip,port);
        pthread_t thread;
        pthread_create(&thread, NULL, peer_thread, &client->peers[i]);
    }
}

void client_bitfield(struct client *client, unsigned char *buf)
{
    int bf_len= client->bitfield_len;
    memcpy(buf,client->bitfield, bf_len*sizeof(unsigned char));
}

int client_reserve_piece(struct client *client, unsigned char *bitfield, uint32_t *piece)
{
    int bf_len= client->bitfield_len;
    int count=0;
    size_t i=0;
    for(i=0;i<bf_len*8;i++){
       if(0==bitfield_is_set(client->reserved,i)&&(0==bitfield_is_set(client->bitfield,i))&&(0!=bitfield_is_set(bitfield,i))){
            count++;
            if(NULL==piece){
                return 1;
            }
            *piece = i;
            bitfield_set(client->reserved,i);
            return 1;
       }
    }
    return 0;
}

void client_unreserve_piece(struct client *client, uint32_t piece)
{
    pthread_mutex_lock(&client->reserved_lock);
    client->reserved[piece/8] &= ~(1 << (8-piece%8-1));
    pthread_mutex_unlock(&client->reserved_lock);
}

void bitfield_set(unsigned char *bitfield, size_t i)
{
    bitfield[i/8] |= (1 << (8-i%8-1));
}

int bitfield_is_set(unsigned char *bitfield, size_t i)
{
    return bitfield[i/8] & (1 << (8-i%8-1));
}

int client_read_request(struct client *client, void *buf, size_t index, size_t offset, size_t len)
{
    pthread_mutex_lock(&client->file_lock);

    FILE *file = fopen(client->torrent->info.name, "rb");
    if (!file) {
        pthread_mutex_unlock(&client->file_lock); 
        return 0;
    }
    size_t file_offset = index * client->torrent->info.piece_length + offset;

    if (fseek(file, file_offset, SEEK_SET) != 0) { 
        fclose(file);
        pthread_mutex_unlock(&client->file_lock);
        return 0;
    }

    if (fread(buf, 1, len, file) != len) { 
        fclose(file);
        pthread_mutex_unlock(&client->file_lock);
        return 0;
    }
    client->uploaded+=len;
    fclose(file);
    pthread_mutex_unlock(&client->file_lock); 

    return 1; 
}

int client_write_piece(struct client *client, void *buf, size_t piece)
{
    pthread_mutex_lock(&client->file_lock);

    FILE *file = fopen(client->torrent->info.name, "r+b");
    if (!file) {
        pthread_mutex_unlock(&client->file_lock); 
        return 0;
    }

    size_t piece_length = metainfo_file_piece_len(client->torrent, piece);
    size_t offset = piece * client->torrent->info.piece_length;

    if (fseek(file, offset, SEEK_SET) != 0) { 
        fclose(file);
        pthread_mutex_unlock(&client->file_lock);
        return 0;
    }

    if (fwrite(buf, 1, piece_length, file) != piece_length) { 
        fclose(file);
        pthread_mutex_unlock(&client->file_lock);
        return 0;
    }

    fclose(file);
    pthread_mutex_unlock(&client->file_lock); 

    client_unreserve_piece(client,piece);

    pthread_mutex_lock(&client->bitfield_lock);
    bitfield_set(client->bitfield,piece);
    pthread_mutex_unlock(&client->bitfield_lock);

    return 1; 

}

