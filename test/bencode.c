#include "unity_fixture.h"
#include "unity.h"
#include "unity_internals.h"
#include <bencode.h>

static struct bencode_value value;

TEST_GROUP(bencode);

TEST_SETUP(bencode) {}

TEST_TEAR_DOWN(bencode) {}


TEST(bencode, valid_string)
{
    TEST_ASSERT_EQUAL(7, bencode_value_decode(&value, "5:hello", 7));
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(5, bencode_value_len(&value));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", bencode_value_str(&value), 5);

    bencode_value_free(&value);
}

TEST(bencode, invalid_string)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "5hello", 6));
}

TEST(bencode, string_negative_len)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "-5:hello", 8));
}

TEST(bencode, string_missing_len)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "hello", 5));
}

TEST(bencode, longer_string)
{
    TEST_ASSERT_EQUAL(7, bencode_value_decode(&value, "5:hellohowis", 12));
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(5, bencode_value_len(&value));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", bencode_value_str(&value), 5);

    bencode_value_free(&value);
}

TEST(bencode, shorter_string)
{
    TEST_ASSERT_EQUAL(5, bencode_value_decode(&value, "3:hello", 5));
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(3, bencode_value_len(&value));
    TEST_ASSERT_EQUAL_STRING_LEN("hel", bencode_value_str(&value), 3);

    bencode_value_free(&value);
}

TEST(bencode, invalid_string_len)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "10:hello", 7));
}

TEST(bencode, valid_number)
{
    TEST_ASSERT_EQUAL(4, bencode_value_decode(&value, "i10e", 4));
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(sizeof(long long), bencode_value_len(&value));
    TEST_ASSERT_EQUAL(10, bencode_value_int(&value));

    bencode_value_free(&value);
}

TEST(bencode, negative_number)
{
    TEST_ASSERT_EQUAL(8, bencode_value_decode(&value, "i-12314e", 8));
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(sizeof(long long), bencode_value_len(&value));
    TEST_ASSERT_EQUAL(-12314, bencode_value_int(&value));

    bencode_value_free(&value);
}

TEST(bencode, zero_number)
{
    TEST_ASSERT_EQUAL(3, bencode_value_decode(&value, "i0e", 3));
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(sizeof(long long), bencode_value_len(&value));
    TEST_ASSERT_EQUAL(0, bencode_value_int(&value));

    bencode_value_free(&value);
}

TEST(bencode, number_missing_trailer)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "i112", 4));
}

TEST(bencode, missing_number)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "i", 1));
}

TEST(bencode, number_leading_zeros)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "i00002e", 7));
}

TEST(bencode, invalid_number)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "ihelloe", 7));
}

TEST(bencode, empty_list)
{
    TEST_ASSERT_EQUAL(2, bencode_value_decode(&value, "le", 2));
    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(0, bencode_value_len(&value));

    bencode_value_free(&value);
}

TEST(bencode, list_single_number)
{
    TEST_ASSERT_EQUAL(6, bencode_value_decode(&value, "li12ee", 6));
    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&value));

    const struct bencode_value *item = bencode_list_get(&value, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(item));
    TEST_ASSERT_EQUAL(12, bencode_value_int(item));

    bencode_value_free(&value);
}

TEST(bencode, list_single_string)
{
    TEST_ASSERT_EQUAL(9, bencode_value_decode(&value, "l5:helloe", 9));
    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&value));

    const struct bencode_value *item = bencode_list_get(&value, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(item));
    TEST_ASSERT_EQUAL(5, bencode_value_len(item));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", bencode_value_str(item), 5);

    bencode_value_free(&value);
}

TEST(bencode, long_list)
{
    size_t len;

    TEST_ASSERT_EQUAL(206, bencode_value_decode(&value, "li0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ee", 206));
    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(&value));
    len = bencode_value_len(&value);
    TEST_ASSERT_EQUAL(68, len);


    for (size_t i = 0; i < len; ++i) {
	const struct bencode_value *item = bencode_list_get(&value, 0);
	TEST_ASSERT_NOT_NULL(item);	
	TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(item));
	TEST_ASSERT_EQUAL(0, bencode_value_int(item));
    }

    bencode_value_free(&value);
}

TEST(bencode, list_mixed_types)
{
    const struct bencode_value *item;

    TEST_ASSERT_EQUAL(30, bencode_value_decode(&value, "l5:helloi12e4:spam4:eggsi-15ee", 30));
    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(5, bencode_value_len(&value));

    item = bencode_list_get(&value, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(item));
    TEST_ASSERT_EQUAL(5, bencode_value_len(item));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", bencode_value_str(item), 5);

    item = bencode_list_get(&value, 1);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(item));
    TEST_ASSERT_EQUAL(12, bencode_value_int(item));

    item = bencode_list_get(&value, 2);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(item));
    TEST_ASSERT_EQUAL(4, bencode_value_len(item));
    TEST_ASSERT_EQUAL_STRING_LEN("spam", bencode_value_str(item), 4);

    item = bencode_list_get(&value, 3);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(item));
    TEST_ASSERT_EQUAL(4, bencode_value_len(item));
    TEST_ASSERT_EQUAL_STRING_LEN("eggs", bencode_value_str(item), 4);

    item = bencode_list_get(&value, 4);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(item));
    TEST_ASSERT_EQUAL(-15, bencode_value_int(item));

    bencode_value_free(&value);
}

TEST(bencode, nested_lists)
{
    const struct bencode_value *item;

    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, "li12el5:helloi52eee", 19));
    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(2, bencode_value_len(&value));

    item = bencode_list_get(&value, 0);
    TEST_ASSERT_NOT_NULL(item);	
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(item));
    TEST_ASSERT_EQUAL(12, bencode_value_int(item));

    item = bencode_list_get(&value, 1);
    TEST_ASSERT_NOT_NULL(item);	
    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(item));
    TEST_ASSERT_EQUAL(2, bencode_value_len(item));

    const struct bencode_value *nitem = bencode_list_get(item, 0);
    TEST_ASSERT_NOT_NULL(nitem);	
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(nitem));
    TEST_ASSERT_EQUAL(5, bencode_value_len(nitem));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", bencode_value_str(nitem), 5);

    nitem = bencode_list_get(item, 1);
    TEST_ASSERT_NOT_NULL(nitem);
    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(nitem));
    TEST_ASSERT_EQUAL(52, bencode_value_int(nitem));

    bencode_value_free(&value);
}

TEST(bencode, invalid_list_item)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "lciaoe", 6));
}

TEST(bencode, invalid_list_at_end)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "li0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0ei0eciaoe", 81));
}

TEST(bencode, non_terminated_list)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "li0e", 4));
}

TEST(bencode, empty_map)
{
    TEST_ASSERT_EQUAL(2, bencode_value_decode(&value, "de", 2));
    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(0, bencode_value_len(&value));

    bencode_value_free(&value);
}

TEST(bencode, map_mapping_int)
{
    struct bencode_value value;

    TEST_ASSERT_EQUAL(13, bencode_value_decode(&value, "d5:helloi12ee", 13));
    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&value));

    const struct bencode_pair *pair = bencode_map_lookup(&value, "hello");
    TEST_ASSERT_NOT_NULL(pair);

    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->key));
    TEST_ASSERT_EQUAL(5, bencode_value_len(&pair->key));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", bencode_value_str(&pair->key), 5);

    TEST_ASSERT_EQUAL(BENCODE_INT, bencode_value_type(&pair->value));
    TEST_ASSERT_EQUAL(12, bencode_value_int(&pair->value));

    bencode_value_free(&value);
}

TEST(bencode, map_mapping_string)
{
    TEST_ASSERT_EQUAL(14, bencode_value_decode(&value, "d5:hello3:cowe", 14));
    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&value));

    const struct bencode_pair *pair = bencode_map_lookup(&value, "hello");
    TEST_ASSERT_NOT_NULL(pair);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->key));
    TEST_ASSERT_EQUAL(5, bencode_value_len(&pair->key));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", bencode_value_str(&pair->key), 5);

    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->value));
    TEST_ASSERT_EQUAL(3, bencode_value_len(&pair->value));
    TEST_ASSERT_EQUAL_STRING_LEN("cow", bencode_value_str(&pair->value), 3);

    bencode_value_free(&value);
}

TEST(bencode, map_mapping_list)
{
    TEST_ASSERT_EQUAL(16, bencode_value_decode(&value, "d4:spaml1:a1:bee", 16));
    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&value));

    const struct bencode_pair *pair = bencode_map_lookup(&value, "spam");
    TEST_ASSERT_NOT_NULL(pair);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->key));
    TEST_ASSERT_EQUAL(4, bencode_value_len(&pair->key));
    TEST_ASSERT_EQUAL_STRING_LEN("spam", bencode_value_str(&pair->key), 4);

    TEST_ASSERT_EQUAL(BENCODE_LIST, bencode_value_type(&pair->value));
    TEST_ASSERT_EQUAL(2, bencode_value_len(&pair->value));

    const struct bencode_value *item = bencode_list_get(&pair->value, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(item));
    TEST_ASSERT_EQUAL(1, bencode_value_len(item));
    TEST_ASSERT_EQUAL_STRING_LEN("a", bencode_value_str(item), 1);

    item = bencode_list_get(&pair->value, 1);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(item));
    TEST_ASSERT_EQUAL(1, bencode_value_len(item));
    TEST_ASSERT_EQUAL_STRING_LEN("b", bencode_value_str(item), 1);

    bencode_value_free(&value);
}

TEST(bencode, map_mapping_map)
{
    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, "d4:spamd4:eggs1:aee", 19));
    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&value));

    const struct bencode_pair *pair = bencode_map_lookup(&value, "spam");
    TEST_ASSERT_NOT_NULL(pair);

    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->key));
    TEST_ASSERT_EQUAL(4, bencode_value_len(&pair->key));
    TEST_ASSERT_EQUAL_STRING_LEN("spam", bencode_value_str(&pair->key), 4);

    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&pair->value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&pair->value));

    const struct bencode_pair *npair = bencode_map_lookup(&pair->value, "eggs");

    TEST_ASSERT_NOT_NULL(npair);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&npair->key));
    TEST_ASSERT_EQUAL(4, bencode_value_len(&npair->key));
    TEST_ASSERT_EQUAL_STRING_LEN("eggs", bencode_value_str(&npair->key), 4);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&npair->value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&npair->value));
    TEST_ASSERT_EQUAL_STRING_LEN("a", bencode_value_str(&npair->value), 1);

    bencode_value_free(&value);
}

TEST(bencode, long_mapping)
{
    TEST_ASSERT_EQUAL(24, bencode_value_decode(&value, "d3:cow3:moo4:spam4:eggse", 24));
    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(2, bencode_value_len(&value));

    const struct bencode_pair *pair = bencode_map_lookup(&value, "cow");
    TEST_ASSERT_NOT_NULL(pair);

    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->key));
    TEST_ASSERT_EQUAL(3, bencode_value_len(&pair->key));
    TEST_ASSERT_EQUAL_STRING_LEN("cow", bencode_value_str(&pair->key), 3);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->value));
    TEST_ASSERT_EQUAL(3, bencode_value_len(&pair->value));
    TEST_ASSERT_EQUAL_STRING_LEN("moo", bencode_value_str(&pair->value), 3);

    pair = bencode_map_lookup(&value, "spam");
    TEST_ASSERT_NOT_NULL(pair);

    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->key));
    TEST_ASSERT_EQUAL(4, bencode_value_len(&pair->key));
    TEST_ASSERT_EQUAL_STRING_LEN("spam", bencode_value_str(&pair->key), 4);
    TEST_ASSERT_EQUAL(BENCODE_STR, bencode_value_type(&pair->value));
    TEST_ASSERT_EQUAL(4, bencode_value_len(&pair->value));
    TEST_ASSERT_EQUAL_STRING_LEN("eggs", bencode_value_str(&pair->value), 4);

    bencode_value_free(&value);
}

TEST(bencode, map_missing_value)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "d4:eggse", 8));
}

TEST(bencode, map_non_str_key)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "di10e4:eggse", 12));
}

TEST(bencode, map_invalid_key)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "d4:spam4:eggse", 6));
}

TEST(bencode, map_not_terminated)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "d4:spam4:eggs", 13));
}

TEST(bencode, map_lookup_missing_key)
{
    TEST_ASSERT_EQUAL(13, bencode_value_decode(&value, "d5:helloi12ee", 13));
    TEST_ASSERT_EQUAL(BENCODE_MAP, bencode_value_type(&value));
    TEST_ASSERT_EQUAL(1, bencode_value_len(&value));

    const struct bencode_pair *pair = bencode_map_lookup(&value, "ciao");
    TEST_ASSERT_NULL(pair);

    bencode_value_free(&value);
}

TEST(bencode, invalid_value)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "someinvalid value", 17));
}

TEST(bencode, empty_string)
{
    TEST_ASSERT_EQUAL(0, bencode_value_decode(&value, "", 0));
}

TEST(bencode, encode_int_null_buf)
{
    TEST_ASSERT_EQUAL(4, bencode_value_decode(&value, "i10e", 4));
    TEST_ASSERT_EQUAL(4, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, encode_negative_int_null_buf)
{
    TEST_ASSERT_EQUAL(7, bencode_value_decode(&value, "i-1000e", 7));
    TEST_ASSERT_EQUAL(7, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, encode_zero_null_buf)
{
    TEST_ASSERT_EQUAL(3, bencode_value_decode(&value, "i0e", 3));
    TEST_ASSERT_EQUAL(3, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, encode_int_single_digit_null_buf)
{
    TEST_ASSERT_EQUAL(3, bencode_value_decode(&value, "i9e", 3));
    TEST_ASSERT_EQUAL(3, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, encode_string_null_buf)
{
    TEST_ASSERT_EQUAL(7, bencode_value_decode(&value, "5:hello", 7));
    TEST_ASSERT_EQUAL(7, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, encode_list_null_buf)
{
    TEST_ASSERT_EQUAL(13, bencode_value_decode(&value, "li10e5:helloe", 13));
    TEST_ASSERT_EQUAL(13, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, nested_lists_null_buf)
{
    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, "li12el5:helloi52eee", 19));
    TEST_ASSERT_EQUAL(19, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, encode_map_null_buf)
{
    TEST_ASSERT_EQUAL(24, bencode_value_decode(&value, "d3:cow3:moo4:spam4:eggse", 24));
    TEST_ASSERT_EQUAL(24, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}


TEST(bencode, encode_nested_map_null_buf)
{
    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, "d4:spamd4:eggs1:aee", 19));
    TEST_ASSERT_EQUAL(19, bencode_value_encode(&value, NULL, 0));

    bencode_value_free(&value);
}

TEST(bencode, encode_int)
{
    const char *expected = "i10e";
    char buf[4];

    TEST_ASSERT_EQUAL(4, bencode_value_decode(&value, expected, 4));
    TEST_ASSERT_EQUAL(4, bencode_value_encode(&value, buf, 4));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 4);

    bencode_value_free(&value);
}

TEST(bencode, encode_negative_int)
{
    const char *expected = "i-1000e";
    char buf[7];

    TEST_ASSERT_EQUAL(7, bencode_value_decode(&value, expected, 7));
    TEST_ASSERT_EQUAL(7, bencode_value_encode(&value, buf, 7));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 7);

    bencode_value_free(&value);
}

TEST(bencode, encode_zero)
{
    const char *expected = "i0e";
    char buf[3];

    TEST_ASSERT_EQUAL(3, bencode_value_decode(&value, expected, 3));
    TEST_ASSERT_EQUAL(3, bencode_value_encode(&value, buf, 3));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 3);

    bencode_value_free(&value);
}

TEST(bencode, encode_int_single_digit)
{
    const char *expected = "i9e";
    char buf[3];

    TEST_ASSERT_EQUAL(3, bencode_value_decode(&value, expected, 3));
    TEST_ASSERT_EQUAL(3, bencode_value_encode(&value, buf, 3));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 3);

    bencode_value_free(&value);
}

TEST(bencode, encode_string)
{
    const char *expected = "5:hello";
    char buf[7];

    TEST_ASSERT_EQUAL(7, bencode_value_decode(&value, expected, 7));
    TEST_ASSERT_EQUAL(7, bencode_value_encode(&value, buf, 7));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 7);

    bencode_value_free(&value);
}

TEST(bencode, encode_list)
{
    const char *expected = "li10e5:helloe";
    char buf[13];

    TEST_ASSERT_EQUAL(13, bencode_value_decode(&value, expected, 13));
    TEST_ASSERT_EQUAL(13, bencode_value_encode(&value, buf, 13));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 13);

    bencode_value_free(&value);
}

TEST(bencode, encode_nested_list)
{
    const char *expected = "li12el5:helloi52eee";
    char buf[19];

    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, expected, 19));
    TEST_ASSERT_EQUAL(19, bencode_value_encode(&value, buf, 19));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 19);

    bencode_value_free(&value);
}

TEST(bencode, encode_map)
{
    const char *expected = "d3:cow3:moo4:spam4:eggse";
    char buf[24];

    TEST_ASSERT_EQUAL(24, bencode_value_decode(&value, expected, 24));
    TEST_ASSERT_EQUAL(24, bencode_value_encode(&value, buf, 24));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 24);

    bencode_value_free(&value);
}

TEST(bencode, encode_nested_map)
{
    const char *expected = "d4:spamd4:eggs1:aee";
    char buf[19];

    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, expected, 19));
    TEST_ASSERT_EQUAL(19, bencode_value_encode(&value, buf, 19));
    TEST_ASSERT_EQUAL_STRING_LEN(expected, buf, 19);

    bencode_value_free(&value);
}

TEST(bencode, encode_int_small_buf)
{
    char buf[4];

    TEST_ASSERT_EQUAL(4, bencode_value_decode(&value, "i10e", 4));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 3));

    bencode_value_free(&value);
}

TEST(bencode, encode_string_small_buf)
{
    char buf[7];

    TEST_ASSERT_EQUAL(7, bencode_value_decode(&value, "5:hello", 7));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 6));

    bencode_value_free(&value);
}

TEST(bencode, encode_list_small_buf)
{
    char buf[19];

    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, "li12el5:helloi52eee", 19));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 18));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 1));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 3));

    bencode_value_free(&value);
}

TEST(bencode, encode_map_small_buf)
{
    char buf[19];

    TEST_ASSERT_EQUAL(19, bencode_value_decode(&value, "d4:spamd4:eggs1:aee", 19));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 18));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 1));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 4));
    TEST_ASSERT_EQUAL(0, bencode_value_encode(&value, buf, 10));

    bencode_value_free(&value);
}


TEST_GROUP_RUNNER(bencode)
{
    RUN_TEST_CASE(bencode, valid_string);
    RUN_TEST_CASE(bencode, invalid_string);
    RUN_TEST_CASE(bencode, string_negative_len);
    RUN_TEST_CASE(bencode, string_missing_len);
    RUN_TEST_CASE(bencode, longer_string);
    RUN_TEST_CASE(bencode, shorter_string);
    RUN_TEST_CASE(bencode, invalid_string_len);

    RUN_TEST_CASE(bencode, valid_number);
    RUN_TEST_CASE(bencode, negative_number);
    RUN_TEST_CASE(bencode, zero_number);
    RUN_TEST_CASE(bencode, number_missing_trailer);
    RUN_TEST_CASE(bencode, missing_number);
    RUN_TEST_CASE(bencode, number_leading_zeros);
    RUN_TEST_CASE(bencode, invalid_number);

    RUN_TEST_CASE(bencode, empty_list);
    RUN_TEST_CASE(bencode, list_single_number);
    RUN_TEST_CASE(bencode, list_single_string);
    RUN_TEST_CASE(bencode, long_list);
    RUN_TEST_CASE(bencode, list_mixed_types);
    RUN_TEST_CASE(bencode, nested_lists);
    RUN_TEST_CASE(bencode, invalid_list_item);
    RUN_TEST_CASE(bencode, invalid_list_at_end);
    RUN_TEST_CASE(bencode, non_terminated_list);

    RUN_TEST_CASE(bencode, empty_map);
    RUN_TEST_CASE(bencode, map_mapping_int);
    RUN_TEST_CASE(bencode, map_mapping_string);
    RUN_TEST_CASE(bencode, map_mapping_list);
    RUN_TEST_CASE(bencode, map_mapping_map);
    RUN_TEST_CASE(bencode, long_mapping);
    RUN_TEST_CASE(bencode, map_missing_value);
    RUN_TEST_CASE(bencode, map_non_str_key);
    RUN_TEST_CASE(bencode, map_invalid_key);
    RUN_TEST_CASE(bencode, map_not_terminated)
    RUN_TEST_CASE(bencode, map_lookup_missing_key);

    RUN_TEST_CASE(bencode, invalid_value);
    RUN_TEST_CASE(bencode, empty_string);
    
    RUN_TEST_CASE(bencode, encode_int_null_buf);
    RUN_TEST_CASE(bencode, encode_negative_int_null_buf);
    RUN_TEST_CASE(bencode, encode_zero_null_buf);
    RUN_TEST_CASE(bencode, encode_int_single_digit_null_buf);
    RUN_TEST_CASE(bencode, encode_string_null_buf);
    RUN_TEST_CASE(bencode, encode_list_null_buf);
    RUN_TEST_CASE(bencode, nested_lists_null_buf);
    RUN_TEST_CASE(bencode, encode_map_null_buf);
    RUN_TEST_CASE(bencode, encode_nested_map_null_buf);

    RUN_TEST_CASE(bencode, encode_int);
    RUN_TEST_CASE(bencode, encode_negative_int);
    RUN_TEST_CASE(bencode, encode_zero);
    RUN_TEST_CASE(bencode, encode_int_single_digit);
    RUN_TEST_CASE(bencode, encode_string);
    RUN_TEST_CASE(bencode, encode_list);
    RUN_TEST_CASE(bencode, encode_nested_list);
    RUN_TEST_CASE(bencode, encode_map);
    RUN_TEST_CASE(bencode, encode_nested_map);

    RUN_TEST_CASE(bencode, encode_int_small_buf);
    RUN_TEST_CASE(bencode, encode_string_small_buf);
    RUN_TEST_CASE(bencode, encode_list_small_buf);
    RUN_TEST_CASE(bencode, encode_map_small_buf);
}
