#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <client.h>
#include <metainfo.h>
#include "unity_fixture.h"
#include "unity.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>


struct memory {
    char *data;
    size_t size;
    size_t cap;
    struct memory *next;
};


static const char *some_peers = "d8:intervali1e5:peersld2:ip9:127.0.0.14:porti6882e7:peer id20:aaaaaaaaaaaaaaaaaaaaed2:ip9:127.0.0.14:porti6883e7:peer id20:bbbbbbbbbbbbbbbbbbbbeee";
static const char *failure = "d7:failure7:failuree";
static const char *res;

static pthread_t tracker;
static pthread_mutex_t mu;
static pthread_cond_t cv;
static struct memory *head;
static struct memory *tail;
CURL *curl;
static const char header_len = 19;
static const char *header = "BitTorrent protocol";
static const char header_reserved[8] = { 0 };



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

static int read_request(struct memory *mem, int sockfd)
{
    ssize_t nread;

    while (1) {
	nread = read(sockfd, mem->data + mem->size, mem->cap - mem->size - 1);
	if (nread == 0) break;
	else if (nread == -1 && errno == EINTR)
	    continue;
	else if (nread == -1)
	    return 0;

	mem->size += nread;
	mem->data[mem->size] = '\0';
	if (mem->size > 4
	    && memcmp(mem->data + mem->size - 4, "\r\n\r\n", 4) == 0)
	    break;

	if (mem->size == mem->cap - 1) {
	    size_t new_cap = mem->cap*2;
	    char *ptr = realloc(mem->data, new_cap);
	    if (ptr == NULL)
		return 0;
	    mem->cap = new_cap;
	    mem->data = ptr;
	}
    }

    return 1;
}

static struct memory *enqueue(void)
{
    struct memory *node = malloc(sizeof(struct memory));
    if (node == NULL) return NULL;

    if ((node->data = malloc(8)) == NULL) {
	free(node);
	return NULL;
    }
    node->cap = 8;
    node->size = 0;
    node->next = NULL;
    if (tail == NULL) head = node;
    else tail->next = node;
    tail = node;
    return node;
}

static struct memory *dequeue(void)
{
    if (head == NULL) return NULL;

    struct memory *node = head;

    head = head->next;
    if (head == NULL) tail = NULL;

    return node;
}

static void tracker_run_cleanup(void *args)
{
    close(*((int *) args));
}

static void *tracker_run(void *args)
{
    int sockfd;
    pthread_barrier_t *barrier = args;
    struct sockaddr_in addr = { 0 };
    char res_buf[1024];
    int enable = 1;
    int len;
	    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8090);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
	pthread_barrier_wait(barrier);
	return NULL;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0
	|| setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0
	|| bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0
	|| listen(sockfd, 1) < 0) {
	pthread_barrier_wait(barrier);
	close(sockfd);
	return NULL;
    }

    pthread_cleanup_push(tracker_run_cleanup, &sockfd);
    pthread_barrier_wait(barrier);

    while (1) {
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	int clientfd = accept(sockfd, NULL, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if (clientfd < 0) continue;
	len = sprintf(res_buf,
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Length: %zu\r\n"
	    "Connection: close\r\n"
	    "\r\n%s", strlen(res), res);
	pthread_mutex_lock(&mu);
	struct memory *mem = enqueue();
	if (mem == NULL || read_request(mem, clientfd) == 0)
	    goto next_connection;

	writen(clientfd, res_buf, len);
    next_connection:
	close(clientfd);
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&mu);
    }

    pthread_cleanup_pop(0);    
    return NULL;
}

static int start_tracker(void)
{
    pthread_barrier_t barrier;

    if (pthread_mutex_init(&mu, NULL) != 0)
	return 0;

    if (pthread_cond_init(&cv, NULL) != 0) {
	pthread_mutex_destroy(&mu);
	return 0;
    }

    pthread_barrier_init(&barrier, NULL, 2);

    if (pthread_create(&tracker, NULL, tracker_run, &barrier) != 0) {
	pthread_barrier_destroy(&barrier);
	pthread_cond_destroy(&cv);
	pthread_mutex_destroy(&mu);
	return 0;
    }

    pthread_barrier_wait(&barrier);
    pthread_barrier_destroy(&barrier);
    return 1;
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

struct server_ctx {
    uint16_t port;
    pthread_barrier_t barrier;
    int error;
    int conn;
};


static void *server_run(void *args)
{
    struct server_ctx *ctx = args;
    struct sockaddr_in addr = { 0 };
    int sockfd;
    int enable = 1;

    ctx->error = 0;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
	ctx->error = 1;
	pthread_barrier_wait(&ctx->barrier);
	return NULL;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0
	|| setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0
	|| bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0
	|| listen(sockfd, 1) < 0) {
	ctx->error = 1;
	pthread_barrier_wait(&ctx->barrier);
	goto cleanup;
    }

    pthread_barrier_wait(&ctx->barrier);
    ctx->conn = accept(sockfd, NULL, NULL);

 cleanup:
    close(sockfd);
    return NULL;
}

static int start_server(pthread_t *server, struct server_ctx *ctx)
{
    pthread_barrier_init(&ctx->barrier, NULL, 2);

    if (pthread_create(server, NULL, server_run, ctx) != 0) {
	pthread_barrier_destroy(&ctx->barrier);
	return 0;
    }

    pthread_barrier_wait(&ctx->barrier);
    pthread_barrier_destroy(&ctx->barrier);
    return ctx->error == 0;
}




TEST_GROUP(tracker);

TEST_SETUP(tracker)
{
    res = some_peers;
    TEST_ASSERT_NOT_EQUAL(0, start_tracker());
    curl = curl_easy_init();
    TEST_ASSERT_NOT_NULL(curl);
}

TEST_TEAR_DOWN(tracker)
{
    struct memory *node;

    pthread_cancel(tracker);
    pthread_join(tracker, NULL);
    pthread_cond_destroy(&cv);
    pthread_mutex_destroy(&mu);
    curl_easy_cleanup(curl);

    while ((node = dequeue()) != NULL) {
	free(node->data);
	free(node);
    }

    remove("existing_file_len_multiple");
    remove("incomplete_file_len_non_multiple");
}


TEST(tracker, existing_file)
{
    struct client *client;
    struct metainfo_file info;
    struct timespec t;
    char *p;
    struct memory *req;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/existing_file_len_multiple",
				       "existing_file_len_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/existing_file_len_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    char *info_hash =
	curl_easy_escape(curl, (const char *) info.info_hash, 20);
    TEST_ASSERT_NOT_NULL(info_hash);

    char *peer_id =
	curl_easy_escape(curl, (const char *) client_peer_id(client), 20);
    TEST_ASSERT_NOT_NULL(peer_id);
    
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }

    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=started"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=0"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=15"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);

    free(req->data);
    free(req);
    curl_free(peer_id);
    curl_free(info_hash);
    client_free(client);
    metainfo_file_free(&info);
}

TEST(tracker, incomplete_file)
{
    struct client *client;
    struct metainfo_file info;
    struct timespec t;
    char *p;
    struct memory *req;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_non_multiple",
				       "incomplete_file_len_non_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    char *info_hash =
	curl_easy_escape(curl, (const char *) info.info_hash, 20);
    TEST_ASSERT_NOT_NULL(info_hash);

    char *peer_id =
	curl_easy_escape(curl, (const char *) client_peer_id(client), 20);
    TEST_ASSERT_NOT_NULL(peer_id);
    
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }
    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=started"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=8"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=5"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);
    free(req->data);
    free(req);
    curl_free(peer_id);
    curl_free(info_hash);
    client_free(client);
    metainfo_file_free(&info);
}

TEST(tracker, existing_file_cleanup)
{
    struct client *client;
    struct metainfo_file info;
    struct timespec t;
    char *p;
    struct memory *req;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/existing_file_len_multiple",
				       "existing_file_len_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/existing_file_len_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    char *info_hash =
	curl_easy_escape(curl, (const char *) info.info_hash, 20);
    TEST_ASSERT_NOT_NULL(info_hash);

    char *peer_id =
	curl_easy_escape(curl, (const char *) client_peer_id(client), 20);
    TEST_ASSERT_NOT_NULL(peer_id);
    
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }

    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=started"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=0"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=15"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);

    free(req->data);
    free(req);
    client_free(client);

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }

    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=stopped"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=0"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=15"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);

    free(req->data);
    free(req);
    curl_free(info_hash);
    curl_free(peer_id);
    metainfo_file_free(&info);
}

TEST(tracker, incomplete_file_cleanup)
{
    struct client *client;
    struct metainfo_file info;
    struct timespec t;
    char *p;
    struct memory *req;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_non_multiple",
				       "incomplete_file_len_non_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    char *info_hash =
	curl_easy_escape(curl, (const char *) info.info_hash, 20);
    TEST_ASSERT_NOT_NULL(info_hash);

    char *peer_id =
	curl_easy_escape(curl, (const char *) client_peer_id(client), 20);
    TEST_ASSERT_NOT_NULL(peer_id);
    
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }
    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=started"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=8"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=5"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);
    free(req->data);
    free(req);
    client_free(client);

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }
    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=stopped"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=8"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=5"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);
    free(req->data);
    free(req);
    curl_free(info_hash);
    curl_free(peer_id);
    metainfo_file_free(&info);
}

TEST(tracker, existing_file_interval)
{
    struct client *client;
    struct metainfo_file info;
    struct timespec t;
    char *p;
    struct memory *req;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/existing_file_len_multiple",
				       "existing_file_len_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/existing_file_len_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    char *info_hash =
	curl_easy_escape(curl, (const char *) info.info_hash, 20);
    TEST_ASSERT_NOT_NULL(info_hash);

    char *peer_id =
	curl_easy_escape(curl, (const char *) client_peer_id(client), 20);
    TEST_ASSERT_NOT_NULL(peer_id);
    
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }

    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=started"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=0"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=15"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);

    free(req->data);
    free(req);

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 2;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }

    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=completed"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=0"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=15"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);

    free(req->data);
    free(req);
    curl_free(info_hash);
    curl_free(peer_id);
    client_free(client);
    metainfo_file_free(&info);
}

TEST(tracker, incomplete_file_interval)
{
    struct client *client;
    struct metainfo_file info;
    struct timespec t;
    char *p;
    struct memory *req;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_non_multiple",
				       "incomplete_file_len_non_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    char *info_hash =
	curl_easy_escape(curl, (const char *) info.info_hash, 20);
    TEST_ASSERT_NOT_NULL(info_hash);

    char *peer_id =
	curl_easy_escape(curl, (const char *) client_peer_id(client), 20);
    TEST_ASSERT_NOT_NULL(peer_id);
    
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }
    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "event=started"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=8"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=5"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);
    free(req->data);
    free(req);

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 2;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }
    TEST_ASSERT_EQUAL_STRING_LEN("GET /announce?", req->data, 14);

    p = strstr(req->data, "info_hash=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(info_hash, p + 10, strlen(info_hash));

    p = strstr(req->data, "peer_id=");
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_STRING_LEN(peer_id, p + 8, strlen(peer_id));

    TEST_ASSERT_NOT_NULL(strstr(req->data, "port=6881"));
    TEST_ASSERT_NULL(strstr(req->data, "event="));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "left=8"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "downloaded=5"));
    TEST_ASSERT_NOT_NULL(strstr(req->data, "uploaded=0"));
    pthread_mutex_unlock(&mu);
    free(req->data);
    free(req);
    curl_free(info_hash);
    curl_free(peer_id);
    client_free(client);
    metainfo_file_free(&info);
}

TEST(tracker, failure)
{
    struct client *client;
    struct metainfo_file info;
    res = failure;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_non_multiple",
				       "incomplete_file_len_non_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    client_free(client);
    metainfo_file_free(&info);
}

TEST(tracker, peer_connections)
{
    struct client *client;
    struct metainfo_file info;
    struct timespec t;
    struct memory *req;
    struct server_ctx peer1 = {
	.port = 6882
    };
    struct server_ctx peer2 = {
	.port = 6883
    };
    pthread_t peer1_tr, peer2_tr;
    char buf[68];

    TEST_ASSERT_NOT_EQUAL(0, start_server(&peer1_tr, &peer1));
    TEST_ASSERT_NOT_EQUAL(0, start_server(&peer2_tr, &peer2));

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_non_multiple",
				       "incomplete_file_len_non_multiple"));
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_NOT_EQUAL(0, client_tracker_connect(client));

    pthread_mutex_lock(&mu);
    if ((req = dequeue()) == NULL) {
    	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += 1;
	TEST_ASSERT_EQUAL(0, pthread_cond_timedwait(&cv, &mu, &t));
	req = dequeue();
    }
    pthread_mutex_unlock(&mu);
    free(req->data);
    free(req);

    pthread_join(peer1_tr, NULL);
    TEST_ASSERT_EQUAL(68, readn(peer1.conn, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(info.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);
    close(peer1.conn);

    pthread_join(peer2_tr, NULL);
    TEST_ASSERT_EQUAL(68, readn(peer2.conn, buf, 68));
    TEST_ASSERT_EQUAL_INT8(header_len, buf[0]);
    TEST_ASSERT_EQUAL_STRING_LEN(header, buf + 1, 19);
    TEST_ASSERT_EQUAL_MEMORY(header_reserved, buf + 20, 8);
    TEST_ASSERT_EQUAL_MEMORY(info.info_hash, buf + 28, 20);
    TEST_ASSERT_EQUAL_MEMORY(client_peer_id(client), buf + 48, 20);
    close(peer2.conn);

    client_free(client);
    metainfo_file_free(&info);
}


TEST_GROUP_RUNNER(tracker)
{
    RUN_TEST_CASE(tracker, existing_file);
    RUN_TEST_CASE(tracker, incomplete_file);
    RUN_TEST_CASE(tracker, existing_file_cleanup);
    RUN_TEST_CASE(tracker, incomplete_file_cleanup);
    RUN_TEST_CASE(tracker, existing_file_interval);
    RUN_TEST_CASE(tracker, incomplete_file_interval);
    RUN_TEST_CASE(tracker, failure);
    RUN_TEST_CASE(tracker, peer_connections);
}
