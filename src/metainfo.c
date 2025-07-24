#include <bencode.h>
#include <metainfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
// Include this header file to do error handling.
#include <openssl/err.h>
// Include this header file to use the SHA family of hash functions.
#include <openssl/sha.h>
//information about the fseek and ftell funcitons:
//https://www.geeksforgeeks.org/fseek-in-c-with-example/
//https://www.geeksforgeeks.org/ftell-c-example/
int pieces_len = 0;
int metainfo_file_read(struct metainfo_file *file, const char *path)
{
    struct bencode_value *node=malloc(sizeof(struct bencode_value));
    FILE *f = fopen(path, "rb");

    if (f == NULL) {return 0;}
    //find the size of the file to create the string, then reset the pointer at the beginning
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    char content[size];
    fseek(f, 0, SEEK_SET);
    fread(content, sizeof(char), size, f);


    //read the first string, that contains "announce"
    bencode_value_decode(node,content,size);


    struct bencode_pair* announce=(struct bencode_pair*)bencode_map_lookup(node,"announce");
    if (NULL==announce|| BENCODE_STR!=bencode_value_type(&(announce->value))) {return 0;}
    file->announce=strdup(announce->value.string);

    //read the second string that contains "info"
    const struct bencode_pair* temp=(struct bencode_pair*)bencode_map_lookup(node,"info");
    if (NULL==temp|| BENCODE_MAP!=bencode_value_type(&(temp->value))) {return 0;}
    const struct bencode_value *info=&temp->value;

    size_t len=bencode_value_encode(info, NULL,0);
    char data[len];
    len=bencode_value_encode(info,data,len);
    // the following code is taken from the usi material: https://www.inf.usi.ch/carzaniga/edu/adv-ntw/openssl_programming.html
    //helped in the debug by: Pasquale Polverino

    // Create a buffer large enough to hold the digest.  The digest
    // has a fixed length depending on the hash function used. In
    // OpenSSL, the different digest lengths are defined as C macros.b

    // Initialize the hashing context. The hashing context will
    // contain all the configurations for the hashshing process.
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    // Configure the hashing context to use the SHA-1 hashing
    // function.
    if(EVP_DigestInit(ctx, EVP_sha1()) != 1
        || EVP_DigestUpdate(ctx, data, len) != 1
        || EVP_DigestFinal(ctx,  file->info_hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Provide the data from which we want to compute the digest.
    // Note that this function can be called multiple times.

    // Once you have provided all the data you want to hash,
    // call the EVP_DigestFinal function to output the resulting
    // digest into the digest buffer.
    // Deallocate the resources for the context
    EVP_MD_CTX_free(ctx);

    //fill name value in info
    temp=(struct bencode_pair*)bencode_map_lookup(info,"name");
    if (NULL==temp|| BENCODE_STR!=bencode_value_type(&(temp->value))) {return 0;}
    file->info.name=strdup(temp->value.string);
    //fill piece length value in info
    temp=(struct bencode_pair*)bencode_map_lookup(info,"piece length");
    if (NULL==temp|| BENCODE_INT!=bencode_value_type(&(temp->value))|| temp->value.number<=0) {return 0;}
    file->info.piece_length=temp->value.number;
    //fill the length value in info
    temp=(struct bencode_pair*)bencode_map_lookup(info,"length");
    if (NULL==temp|| BENCODE_INT!=bencode_value_type(&(temp->value)) || temp->value.number<=0) {return 0;}
    file->info.length=temp->value.number;
    //fill the pieces file in info
    temp=(struct bencode_pair*)bencode_map_lookup(info,"pieces");
    if (NULL==temp|| BENCODE_STR!=bencode_value_type(&(temp->value)) || temp->value.stringlen%20!=0) {return 0;}
    pieces_len=temp->value.stringlen;
    file->info.pieces=temp->value.string;


    fclose(f);
    return size;
}

void metainfo_file_free(struct metainfo_file *file)
{ 
    free(file->announce);
    free(file->info.name);
    free(file->info.pieces);
    file->info.length=0;
    file->info.piece_length=0;
 }

const char *metainfo_file_piece_hash(const struct metainfo_file *file, size_t i)
{
    const char * hash=&file->info.pieces[20*i];
    return hash;
}

size_t metainfo_file_pieces_count(const struct metainfo_file *file)
{
    return pieces_len/20;
}

size_t metainfo_file_piece_len(const struct metainfo_file *file, size_t i)
{
    // TODO return info.piece_length
    // TODO in case it is the last piece, return the difference between
    // info.length and file->info.piece_length*i
    if(i>=metainfo_file_pieces_count(file)){
        return 0;
    }
    return (i<metainfo_file_pieces_count(file)-1)?file->info.piece_length:(file->info.length-file->info.piece_length*i);
}


int metainfo_file_verify(const struct metainfo_file *file, void *buf, size_t len, size_t i)
{
    /*
     * TODO create a EVP_MD_CTX, initialize the digest operation,
     * update the digest with buf, and finalize in this order. Get the
     * hash value for piece i, and compare byte by byte the piece hash
     * with the digest you obtained. Return 1 if they are the same
     * otherwise return 0.
     */
    unsigned char res[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    if(EVP_DigestInit(ctx, EVP_sha1()) != 1
        || EVP_DigestUpdate(ctx, buf, len) != 1
        || EVP_DigestFinal(ctx,  res, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);

    return (0==memcmp(res,metainfo_file_piece_hash(file,i),20))?1:0;
}
