#include <peer_listener.h>
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
#include <client.h>


struct tracker_connection{
    long long interval;//how long to wait between requests
    pthread_t thread;

};

struct peer_listener{
    int sockfd;
    pthread_t thread;
    struct client *client;
    pthread_barrier_t barrier; 
};
// Thread function to handle peer connections
void *peer_listener_thread(void *arg)
{
    
    struct peer_listener *listener = (struct peer_listener *)arg;
    int srv = listener->sockfd;
    struct client *client = listener->client;

    // Signal that the server is ready
    pthread_barrier_wait(&listener->barrier);

    for (;;) {
        int conn = accept(srv, NULL, NULL);
        if (conn < 0) {
            perror("accept failed");
            continue;
        }
        
        client_add_connected_peer(client, conn);
        
    }
    return NULL;
}

struct peer_listener *peer_listener_new(struct client *client)
{
    uint16_t port = client->port;
    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    int srv = socket(AF_INET6, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket failed");
        return NULL;
    }
    // Enable address reuse and disable IPv6-only
    int enable = 1, disable = 0;
    if (setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0
        || setsockopt(srv, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0
        || setsockopt(srv, IPPROTO_IPV6, IPV6_V6ONLY, &disable, sizeof(int)) < 0) {
        perror("setsockopt failed");
        close(srv);
        return NULL;
    }


    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(srv);
        return NULL;
    }

    if (listen(srv, 10) < 0) {
        perror("listen failed");
        close(srv);
        return NULL;
    }

    struct peer_listener *listener = malloc(sizeof(struct peer_listener));
    if (!listener) {
        perror("malloc failed");
        close(srv);
        return NULL;
    }

    client->listener=listener;
    listener->sockfd = srv;
    listener->client = client;
    pthread_barrier_init(&listener->barrier, NULL, 2);  // Barrier for synchronization

    // Create the listener thread
    if (pthread_create(&listener->thread, NULL, peer_listener_thread, listener) != 0) {
        perror("pthread_create failed");
        close(srv);
        free(listener);
        return NULL;
    }

    // Wait for the listener thread to signal that it has started
    pthread_barrier_wait(&listener->barrier);
    pthread_barrier_destroy(&listener->barrier);

    

    return listener;
}

void peer_listener_free(struct peer_listener *listener)
{
    if (listener) {
        if (listener->sockfd != -1) {
            close(listener->sockfd);
        }
        if (listener->thread != 0) {
            pthread_cancel(listener->thread);
            pthread_join(listener->thread, NULL);
        }
        free(listener);
    }
}
