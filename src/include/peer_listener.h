#ifndef PEER_LISTENER_H_INCLUDED
#define PEER_LISTENER_H_INCLUDED

#include <client.h>

struct peer_listener;

/**
 * It allocates structure holding the context for the server accepting
 * peer connections.  It also starts the server thread.
 *
 * @param client A pointer to the client structure.
 * @return A pointer to the peer listener server context on success;
 * otherwise, it returns NULL.
 */
struct peer_listener *peer_listener_new(struct client *client);

/**
 * It deallocates all the resources for the server context.
 * It also stops the server thread.
 *
 * @param server A pointer to a server context.
 */
void peer_listener_free(struct peer_listener *server);

#endif
