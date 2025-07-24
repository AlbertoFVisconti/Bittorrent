#ifndef TRACKER_CONNECTION_H_INCLUDED
#define TRACKER_CONNECTION_H_INCLUDED

#include <client.h>

struct tracker_connection;

/**
 * It allocates structure holding the context for polling the tracker.
 * It also starts the tracker polling thread.
 *
 * @param client A pointer to the client structure.
 * @return A pointer to the tracker connection context on success;
 * otherwise, it returns NULL.
 */
struct tracker_connection *tracker_connection_new(struct client *client);

/**
 * It deallocates all the resources for the tracker connection context.
 * It also stops the tracker polling thread.
 *
 * @param connecntion A pointer to a tracker connection context.
 */
void tracker_connection_free(struct tracker_connection *connection);

#endif
