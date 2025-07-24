#ifndef BENCODE_H_INCLUDED
#define BENCODE_H_INCLUDED

#include <stdlib.h>

enum bencode_t {
    BENCODE_STR,
    BENCODE_INT,
    BENCODE_LIST,
    BENCODE_MAP,
};

struct bencode_list;
struct bencode_map;
struct bencode_str;

struct bencode_value {
    enum bencode_t type;
    char* string;
    int stringlen;
    long long number;
    //list need to be able to scale both horizontally (more elements) and vertically (nested lists)
    struct bencode_value* next;
    struct bencode_value* contained;
    //map with key, value pairs implemented with a dynamic array of pointers
    struct bencode_pair **dictionary;
    int dictionary_size;
};

struct bencode_pair {
    struct bencode_value key;
    struct bencode_value value;
};

/**
 * Release all the memory internally used by value. Note that value
 * should not be deallocated.
 *
 * @param value A pointer to a bencoded value.
 */
void bencode_value_free(struct bencode_value *value);

/**
 * Decode a bencoded string into value and returns the number of bytes
 * from enc_val decoded.
 *
 * @param value An output parameter that will contain the decoded value.
 * @param enc_val A bencode string to decode.
 * @param n The length of enc_val in bytes.
 * @return The number of bytes decoded from enc_val. If decoding
 * fails it should return 0.
 */
size_t bencode_value_decode(struct bencode_value *value, const char *enc_val, size_t n);

/**
 * Encode a bencoded value into buf using at most n bytes.
 *
 * @param value The bencoded value to encode.
 * @param buf The output buffer for the encoding.
 * @param n The length of buf in bytes.
 * @return The number of bytes used in the encoding. If the encoding
 * fails it should return 0. The encoding might fail because n
 * is not large enough to contain the entire value bencoded.
 */
size_t bencode_value_encode(const struct bencode_value *value, char *buf, size_t n);

/**
 * Get the type of value.
 *
 * @param value The bencoded value.
 * @return The type of value.
 */
enum bencode_t bencode_value_type(const struct bencode_value *value);

/**
 * Get the length of the value. If the value is a string it
 * returns the length of the string in bytes.  If the value is an
 * integer it returns the size of an integer. If the value is a list
 * it returns the length of the list. If the value is a map, it
 * returns the number of mappings.
 *
 * @param value The bencoded value.
 * @return The length of the value.
 */
size_t bencode_value_len(const struct bencode_value *value);

/**
 * Get the value as an integer. It only makes sense if the value is
 * BENCODE_INT.  Otherwise, its behavior is undefined.
 *
 * @param value The bencoded value.
 * @return The value as an integer.
 */
long long bencode_value_int(const struct bencode_value *value);

/**
 * Get the value as a string. It only makes sense if the value is
 * BENCODE_STR.  Otherwise, its behavior is undefined.
 *
 * @param value The bencoded value.
 * @return The value as a string.
 */
const char *bencode_value_str(const struct bencode_value *value);

/**
 * Get the element at index i from a bencode list. It only makes sense
 * if the value is BENCODE_LIST.  Otherwise, its behavior is
 * undefined.
 *
 * @param value The bencoded value.
 * @param i The index to lookup.
 * @return The bencoded value at index i.
 */
const struct bencode_value *bencode_list_get(const struct bencode_value *value, size_t i);

/**
 * Get the mapping associated with key from a bencode map. It only makes sense
 * if the value is BENCODE_MAP.  Otherwise, its behavior is
 * undefined.
 *
 * @param value The bencoded value.
 * @param key The key to lookup.
 * @return The pair containg the bencoded key and its associated
 * bencoded value. If no mapping is found for key it should return
 * NULL.
 */
const struct bencode_pair *bencode_map_lookup(const struct bencode_value *value, const char *key);

#endif
