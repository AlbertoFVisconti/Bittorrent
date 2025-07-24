#include <client.h>
#include <metainfo.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <peer_listener.h>

static int running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

int main(int argc, char *argv[])
{

    //ensure that the user provides a .torrent file as argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.torrent>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    const char *ext = strrchr(filename, '.');

    if (!ext || strcmp(ext, ".torrent") != 0) {
        fprintf(stderr, "Error: Argument must be a .torrent file\n");
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    //read the .torrent file
    struct metainfo_file file;
    if(0==metainfo_file_read(&file, filename)){
        fprintf(stderr,"Error reading the file \n");
        return EXIT_FAILURE;
    }
    printf("read file\n");
    
    //create a client
    struct client *client;
    client=client_new(&file,6881);
    if(NULL==client){
        fprintf(stderr,"Error creating the client \n");
        return EXIT_FAILURE;
    }
    printf("created client\n");

    // start listening on connecting peers
    struct peer_listener *server;
    server=peer_listener_new(client); 
    if(NULL==server){
        fprintf(stderr,"Error listening for peers\n");
        return EXIT_FAILURE;
    }
    printf("started listening\n");

    // connect to the tracker
    if(0==client_tracker_connect(client)){
        fprintf(stderr,"Error connecting to tracker\n");
        return EXIT_FAILURE;
    }
    printf("connected to tracker\n");

    //connect and comunicate with peers
    while (running){
        if(!strcmp(client->download_status,"completed")){
            running=0;
        }
        
    }
    


    // TODO cleanup
    client_free(client);
    metainfo_file_free(&file);
    peer_listener_free(server);
    return EXIT_SUCCESS;
}
