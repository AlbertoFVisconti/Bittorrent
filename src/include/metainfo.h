#ifndef METAINFO_H_INCLUDED
#define METAINFO_H_INCLUDED

#include <stddef.h>
#include <openssl/sha.h>

struct metainfo_info {
    char *name;
    size_t piece_length;
    size_t length;
    char *pieces;
};

struct metainfo_file {
    char *announce;
    struct metainfo_info info;
    unsigned char info_hash[SHA_DIGEST_LENGTH];
};

int metainfo_file_read(struct metainfo_file *file, const char *path);
void metainfo_file_free(struct metainfo_file *file);
const char *metainfo_file_piece_hash(const struct metainfo_file *file, size_t i);
size_t metainfo_file_pieces_count(const struct metainfo_file *file);
size_t metainfo_file_piece_len(const struct metainfo_file *file, size_t i);
int metainfo_file_verify(const struct metainfo_file *file, void *buf, size_t n, size_t i);

#endif
