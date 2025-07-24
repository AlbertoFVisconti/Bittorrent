#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <client.h>
#include <metainfo.h>
#include "unity_fixture.h"
#include "unity.h"

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


TEST_GROUP(client);

TEST_SETUP(client) {}

TEST_TEAR_DOWN(client)
{
    remove("sample.txt");

    remove("existing_file_len_multiple");
    remove("existing_file_len_non_multiple");

    remove("incomplete_file_len_multiple");
    remove("incomplete_file_len_non_multiple");

    remove("incomplete_file_len_multiple_last");
    remove("incomplete_file_len_non_multiple_last");

    remove("shorter_file_len_multiple");
    remove("shorter_file_len_non_multiple");

    remove("longer_file_len_multiple");
    remove("longer_file_len_non_multiple");

    remove("ubuntu-24.10-desktop-amd64.iso");
}


TEST(client, peer_id_generation)
{
    struct metainfo_file info;
    unsigned char buf[20];
    const unsigned char *peer_id;
    struct client *client;

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/simple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_EQUAL(6881, client_port(client));
    memcpy(buf, client_peer_id(client), 20);
    client_free(client);

    client = client_new(&info, 6832);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_EQUAL(6832, client_port(client));
    peer_id = client_peer_id(client);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(buf, peer_id, 20),
				  "The peer ID must be randomly generated");

    client_free(client);
    metainfo_file_free(&info);
}

TEST(client, port)
{
    struct metainfo_file info;
    struct client *client;

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/simple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_EQUAL(6881, client_port(client));
    client_free(client);

    client = client_new(&info, 6832);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_EQUAL(6832, client_port(client));

    client_free(client);
    metainfo_file_free(&info);
}

TEST(client, torrent_file)
{
    struct metainfo_file info;
    struct client *client;

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/simple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);
    TEST_ASSERT_EQUAL_STRING(info.announce, client_torrent(client)->announce);
    TEST_ASSERT_EQUAL_MEMORY(info.info_hash, client_torrent(client)->info_hash, 20);

    client_free(client);
    metainfo_file_free(&info);
}

TEST(client, not_existing_file)
{
    struct metainfo_file info;
    struct client *client;

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/simple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(0, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(info.info.length, client_left(client));

    client_free(client);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);
    TEST_ASSERT_EQUAL(EOF, fgetc(fp));

    fclose(fp);
    metainfo_file_free(&info);
}

TEST(client, existing_file_len_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/existing_file_len_multiple",
				       "existing_file_len_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/existing_file_len_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(info.info.length, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(0, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);
    TEST_ASSERT_EQUAL(EOF, fgetc(fp));

    fclose(fp);

    fp = fopen("test/existing_file_len_multiple", "r");
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, existing_file_len_non_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/existing_file_len_non_multiple",
				       "existing_file_len_non_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/existing_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(info.info.length, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(0, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);
    TEST_ASSERT_EQUAL(EOF, fgetc(fp));

    fclose(fp);

    fp = fopen("test/existing_file_len_non_multiple", "r");
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, incomplete_file_len_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_multiple",
				       "incomplete_file_len_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(5, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(10, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);
    TEST_ASSERT_EQUAL(EOF, fgetc(fp));

    fclose(fp);

    fp = fopen("test/incomplete_file_len_multiple", "r");
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, incomplete_file_len_non_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_non_multiple",
				       "incomplete_file_len_non_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(5, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(8, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);
    TEST_ASSERT_EQUAL(EOF, fgetc(fp));

    fclose(fp);

    fp = fopen("test/incomplete_file_len_non_multiple", "r");
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, incomplete_file_len_multiple_last)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_multiple_last",
				       "incomplete_file_len_multiple_last"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_multiple_last.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(5, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(10, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);
    TEST_ASSERT_EQUAL(EOF, fgetc(fp));

    fclose(fp);

    fp = fopen("test/incomplete_file_len_multiple_last", "r");
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, incomplete_file_len_non_multiple_last)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/incomplete_file_len_non_multiple_last",
				       "incomplete_file_len_non_multiple_last"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/incomplete_file_len_non_multiple_last.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(3, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(10, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);
    TEST_ASSERT_EQUAL(EOF, fgetc(fp));

    fclose(fp);

    fp = fopen("test/incomplete_file_len_non_multiple_last", "r");
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, shorter_file_len_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/shorter_file_len_multiple",
				       "shorter_file_len_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/shorter_file_len_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(5, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(10, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);

    fclose(fp);

    fp = fopen("test/shorter_file_len_multiple", "r");
    TEST_ASSERT_NOT_NULL(fp);
    TEST_ASSERT_EQUAL(fread(buf + info.info.length, 1, info.info.length, fp), n);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, n);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, shorter_file_len_non_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/shorter_file_len_non_multiple",
				       "shorter_file_len_non_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/shorter_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(5, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(8, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);

    fclose(fp);

    fp = fopen("test/shorter_file_len_non_multiple", "r");
    TEST_ASSERT_NOT_NULL(fp);
    TEST_ASSERT_EQUAL(fread(buf + info.info.length, 1, info.info.length, fp), n);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, n);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, longer_file_len_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/longer_file_len_multiple",
				       "longer_file_len_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/longer_file_len_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(5, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(10, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);

    fclose(fp);

    fp = fopen("test/longer_file_len_multiple", "r");
    memset(buf + info.info.length, 0, info.info.length);
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, longer_file_len_non_multiple)
{
    struct metainfo_file info;
    struct client *client;
    char *buf;

    TEST_ASSERT_NOT_EQUAL(0, copy_file("test/longer_file_len_non_multiple",
				       "longer_file_len_non_multiple"));

    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info,
						"test/longer_file_len_non_multiple.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(5, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(8, client_left(client));

    client_free(client);

    buf = malloc(info.info.length*2);
    TEST_ASSERT_NOT_NULL(buf);

    FILE *fp = fopen(info.info.name, "r");
    TEST_ASSERT_NOT_NULL(fp);

    size_t n = fread(buf, 1, info.info.length, fp);
    TEST_ASSERT_EQUAL(info.info.length, n);

    fclose(fp);

    fp = fopen("test/longer_file_len_non_multiple", "r");
    memset(buf + info.info.length, 0, info.info.length);
    fread(buf + info.info.length, 1, info.info.length, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_MEMORY(buf + info.info.length, buf, info.info.length);

    free(buf);
    metainfo_file_free(&info);
}

TEST(client, ubuntu)
{
    struct metainfo_file info;
    struct client *client;

    remove("ubuntu-24.10-desktop-amd64.iso");
    TEST_ASSERT_NOT_EQUAL(0, metainfo_file_read(&info, "test/ubuntu.torrent"));

    client = client_new(&info, 6881);
    TEST_ASSERT_NOT_NULL(client);

    TEST_ASSERT_EQUAL(0, client_downloaded(client));
    TEST_ASSERT_EQUAL(0, client_uploaded(client));
    TEST_ASSERT_EQUAL(5665497088, client_left(client));

    client_free(client);
    metainfo_file_free(&info);
}


TEST_GROUP_RUNNER(client)
{
    RUN_TEST_CASE(client, peer_id_generation);
    RUN_TEST_CASE(client, port);
    RUN_TEST_CASE(client, torrent_file);

    RUN_TEST_CASE(client, not_existing_file);
    RUN_TEST_CASE(client, existing_file_len_multiple);
    RUN_TEST_CASE(client, existing_file_len_non_multiple);
    RUN_TEST_CASE(client, incomplete_file_len_multiple);
    RUN_TEST_CASE(client, incomplete_file_len_non_multiple);

    RUN_TEST_CASE(client, incomplete_file_len_multiple_last);
    RUN_TEST_CASE(client, incomplete_file_len_non_multiple_last);

    RUN_TEST_CASE(client, shorter_file_len_multiple);
    RUN_TEST_CASE(client, shorter_file_len_non_multiple);
    
    RUN_TEST_CASE(client, longer_file_len_multiple);
    RUN_TEST_CASE(client, longer_file_len_non_multiple);

    RUN_TEST_CASE(client, ubuntu);
}
