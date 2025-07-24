#include <tracker_connection.h>
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

struct tracker_connection{
  long long interval;//how long to wait between requests
  pthread_t thread;

};

//resources:
//https://github.com/portfoliocourses/c-example-code/blob/main/libcurl_examples/query_parameters.c
//https://github.com/portfoliocourses/c-example-code/blob/main/libcurl_examples/store_http_response_into_string.c
typedef struct
{
  char *string;
  size_t size;
} Response;
// This function is called repeatedly by curl_easy_perform() to handle chunks of the response data.
size_t write_chunk(void *data, size_t size, size_t nmemb, void *userdata)
{
  // Though the official libcurl documentation tells us size will always be 1, 
  // the idea is that nmemb is the amount of 'something' and size is the size 
  // of that 'something' in bytes.  So we multiply size by nmemb to get the 
  // total real size of the chunk, but practically real_size == nmemb.
  size_t real_size = size * nmemb; 
  
  // The function prototype requires the 4th parameter to be a void pointer, but
  // WE know it's really a pointer to a Response struct so we type cast it here.
  Response *response = (Response *) userdata; 
  
  // Attempt to reallocate space for a larger block of memory for the Response 
  // struct string member to point to... we increase the size of the block of 
  // memory by the existing size PLUS the size of the chunk and 1 more byte to
  // store the null terminator.
  char *ptr = realloc(response->string, response->size + real_size + 1);

  // If re-allocation fails realloc() will return NULL, in this case we can 
  // return either 0 or CURL_WRITE_FUNCTION_ERROR to stop the transfer.
  if (ptr == NULL)
  {
    // return 0;
    return CURL_WRITEFUNC_ERROR;  
  }
  
  // If re-allocation was successful, set the string member of the Response 
  // struct to point to the enlarged block of memory.
  response->string = ptr;
  
  // Append the new chunk of char data to the existing string using memcpy.  The
  // source is set to the memory address of the last index in the existing 
  // string so that we begin copying the new chunk here.  This last index will 
  // be the null terminator of the existing string (unless it is the first time
  // that write_chunk is called, in which case we have no string data stored
  // yet).  We copy to this "source address" from the destination address "data"
  // where the chunk is stored, copying the size of the chunk (real_size).
  memcpy(&(response->string[response->size]), data, real_size);

  // Add the size of the chunk to the size member to keep track of the size of
  // the string received.
  response->size += real_size;

  // Set the last character of the block of memory for the string to the null 
  // terminator to complete the string.  We can use either '\0' or 0.
  response->string[response->size] = 0; // '\0';
   
  // Return the size of the chunk in bytes as required by libcurl
  return real_size;
}


struct tracker_connection *tracker_connection_new(struct client *client)
{

    // Stores the CURL handle used to manage the request and easy API session    
  CURL *curl;

  // Stores the return value of the call to curl_easy_perform()
  CURLcode result;

  // Starts the session, return the curl handle we'll use to setup the request
  curl = curl_easy_init();

  // If curl_easy_init() fails the function returns an error, we exit with an 
  // error message and status in this case
  if (curl == NULL)
  {
    return NULL;
  }

  Response response;
  response.string = malloc(1);  // Initial memory allocation (1 byte)
  response.size = 0;

   // Stores the request URL
   char url[2048];
   char *info_hash_safe=curl_easy_escape(curl,(char *)client->torrent->info_hash,20);
   char *peer_id_safe=curl_easy_escape(curl,(char *)client->peer_id,20);
   char *event=client->download_status;
   
   
    
   // Call sprintf() to build a complete URL string, using the now 'safe' URL 
  // encoded values for our query parameters.  We could apply the same process 
  // to ensure the keys are also URL encoded if there is a concern that they may
  // also contain reserved characters.  sprintf() uses a format string like 
  // printf() except the resulting string will be stored in the url char array.
    if(event!=NULL && 0==strcmp(event,"")){
      sprintf(url, "%s?info_hash=%s&peer_id=%s&port=%hu&uploaded=%zu&downloaded=%zu&left=%zu",
        client->torrent->announce,info_hash_safe,peer_id_safe,client->port,client->uploaded,client->downloaded, client->missing);
    }
    else{
      sprintf(url, "%s?info_hash=%s&peer_id=%s&port=%hu&uploaded=%zu&downloaded=%zu&left=%zu&event=%s",
        client->torrent->announce,info_hash_safe,peer_id_safe,client->port,client->uploaded,client->downloaded, client->missing,event);

    }


    curl_easy_setopt(curl, CURLOPT_URL, url); 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_chunk); 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,20);

    result = curl_easy_perform(curl);
    if (result != CURLE_OK)
    {
        return NULL;
    }

    //response arrived
    struct bencode_value *torrent_response=malloc(sizeof(struct bencode_value));
    if(0==bencode_value_decode(torrent_response,response.string,response.size )){
        return NULL;
    }

    struct tracker_connection *res=malloc(sizeof(struct tracker_connection));
    res->thread=0;
    if(NULL!=bencode_map_lookup(torrent_response,"failure")){
      res->interval=-123;
      return res;
    }
    if(NULL==bencode_map_lookup(torrent_response,"interval")|| 
        NULL==bencode_map_lookup(torrent_response,"peers")){
        return NULL;
    }


    const struct bencode_value *peers=&bencode_map_lookup(torrent_response,"peers")->value;
    
    
    res->interval=bencode_map_lookup(torrent_response,"interval")->value.number;
    client_add_bencoded_peer_list(client,peers);


    // We call curl_free() to free the dynamically allocated strings v1safe and 
    // v2safe.
    curl_free(info_hash_safe);
    curl_free(peer_id_safe);

    // We call curl_easy_cleanup() to complete the session.
    curl_easy_cleanup(curl); 
    return res;
}

void tracker_connection_free(struct tracker_connection *connection)
{ 
  if(0!=connection->thread){
    pthread_cancel(connection->thread);
    pthread_join(connection->thread,NULL);
  }
  connection->interval=0;
  free(connection);
}
