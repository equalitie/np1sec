#include <glib.h>
#include <check.h>
#include <stdlib.h>
#include <string.h>

#undef HAVE_DBUS

#include "tests.h"

#include "../cipher.h"

/******************************************************************************
 * MD4 Tests
 *****************************************************************************/
#define MD4_TEST(data, digest) { \
	PurpleCipher *cipher = NULL; \
	PurpleCipherContext *context = NULL; \
	gchar cdigest[33]; \
	gboolean ret = FALSE; \
	\
	cipher = purple_ciphers_find_cipher("md4"); \
	context = purple_cipher_context_new(cipher, NULL); \
	purple_cipher_context_append(context, (guchar *)(data), strlen((data))); \
	\
	ret = purple_cipher_context_digest_to_str(context, sizeof(cdigest), cdigest, \
	                                        NULL); \
	\
	fail_unless(ret == TRUE, NULL); \
	\
	fail_unless(strcmp((digest), cdigest) == 0, NULL); \
	\
	purple_cipher_context_destroy(context); \
}

START_TEST(test_md4_empty_string) {
	MD4_TEST("", "31d6cfe0d16ae931b73c59d7e0c089c0");
}
END_TEST

START_TEST(test_md4_a) {
	MD4_TEST("a", "bde52cb31de33e46245e05fbdbd6fb24");
}
END_TEST

START_TEST(test_md4_abc) {
	MD4_TEST("abc", "a448017aaf21d8525fc10ae87aa6729d");
}
END_TEST

START_TEST(test_md4_message_digest) {
	MD4_TEST("message digest", "d9130a8164549fe818874806e1c7014b");
}
END_TEST

START_TEST(test_md4_a_to_z) {
	MD4_TEST("abcdefghijklmnopqrstuvwxyz",
			 "d79e1c308aa5bbcdeea8ed63df412da9");
}
END_TEST

START_TEST(test_md4_A_to_Z_a_to_z_0_to_9) {
	MD4_TEST("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			 "043f8582f241db351ce627e153e7f0e4");
}
END_TEST

START_TEST(test_md4_1_to_0_8_times) {
	MD4_TEST("123456789012345678901234567890123456789012345678901234567890"
			 "12345678901234567890",
			 "e33b4ddc9c38f2199c3e7b164fcc0536");
}
END_TEST


/******************************************************************************
 * MD5 Tests
 *****************************************************************************/
#define MD5_TEST(data, digest) { \
	PurpleCipher *cipher = NULL; \
	PurpleCipherContext *context = NULL; \
	gchar cdigest[33]; \
	gboolean ret = FALSE; \
	\
	cipher = purple_ciphers_find_cipher("md5"); \
	context = purple_cipher_context_new(cipher, NULL); \
	purple_cipher_context_append(context, (guchar *)(data), strlen((data))); \
	\
	ret = purple_cipher_context_digest_to_str(context, sizeof(cdigest), cdigest, \
	                                        NULL); \
	\
	fail_unless(ret == TRUE, NULL); \
	\
	fail_unless(strcmp((digest), cdigest) == 0, NULL); \
	\
	purple_cipher_context_destroy(context); \
}

START_TEST(test_md5_empty_string) {
	MD5_TEST("", "d41d8cd98f00b204e9800998ecf8427e");
}
END_TEST

START_TEST(test_md5_a) {
	MD5_TEST("a", "0cc175b9c0f1b6a831c399e269772661");
}
END_TEST

START_TEST(test_md5_abc) {
	MD5_TEST("abc", "900150983cd24fb0d6963f7d28e17f72");
}
END_TEST

START_TEST(test_md5_message_digest) {
	MD5_TEST("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
}
END_TEST

START_TEST(test_md5_a_to_z) {
	MD5_TEST("abcdefghijklmnopqrstuvwxyz",
			 "c3fcd3d76192e4007dfb496cca67e13b");
}
END_TEST

START_TEST(test_md5_A_to_Z_a_to_z_0_to_9) {
	MD5_TEST("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			 "d174ab98d277d9f5a5611c2c9f419d9f");
}
END_TEST

START_TEST(test_md5_1_to_0_8_times) {
	MD5_TEST("123456789012345678901234567890123456789012345678901234567890"
			 "12345678901234567890",
			 "57edf4a22be3c955ac49da2e2107b67a");
}
END_TEST

/******************************************************************************
 * SHA-1 Tests
 *****************************************************************************/
#define SHA1_TEST(data, digest) { \
	PurpleCipher *cipher = NULL; \
	PurpleCipherContext *context = NULL; \
	gchar cdigest[41]; \
	gboolean ret = FALSE; \
	gchar *input = data; \
	\
	cipher = purple_ciphers_find_cipher("sha1"); \
	context = purple_cipher_context_new(cipher, NULL); \
	\
	if (input) { \
		purple_cipher_context_append(context, (guchar *)input, strlen(input)); \
	} else { \
		gint j; \
		guchar buff[1000]; \
		\
		memset(buff, 'a', 1000); \
		\
		for(j = 0; j < 1000; j++) \
			purple_cipher_context_append(context, buff, 1000); \
	} \
	\
	ret = purple_cipher_context_digest_to_str(context, sizeof(cdigest), cdigest, \
	                                        NULL); \
	\
	fail_unless(ret == TRUE, NULL); \
	\
	fail_unless(strcmp((digest), cdigest) == 0, NULL); \
	\
	purple_cipher_context_destroy(context); \
}

START_TEST(test_sha1_empty_string) {
	SHA1_TEST("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}
END_TEST

START_TEST(test_sha1_a) {
	SHA1_TEST("a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
}
END_TEST

START_TEST(test_sha1_abc) {
	SHA1_TEST("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
}
END_TEST

START_TEST(test_sha1_abcd_gibberish) {
	SHA1_TEST("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			  "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}
END_TEST

START_TEST(test_sha1_1000_as_1000_times) {
	SHA1_TEST(NULL, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}
END_TEST

/******************************************************************************
 * SHA-256 Tests
 *****************************************************************************/
#define SHA256_TEST(data, digest) { \
	PurpleCipher *cipher = NULL; \
	PurpleCipherContext *context = NULL; \
	gchar cdigest[65]; \
	gboolean ret = FALSE; \
	gchar *input = data; \
	\
	cipher = purple_ciphers_find_cipher("sha256"); \
	context = purple_cipher_context_new(cipher, NULL); \
	\
	if (input) { \
		purple_cipher_context_append(context, (guchar *)input, strlen(input)); \
	} else { \
		gint j; \
		guchar buff[1000]; \
		\
		memset(buff, 'a', 1000); \
		\
		for(j = 0; j < 1000; j++) \
			purple_cipher_context_append(context, buff, 1000); \
	} \
	\
	ret = purple_cipher_context_digest_to_str(context, sizeof(cdigest), cdigest, \
	                                        NULL); \
	\
	fail_unless(ret == TRUE, NULL); \
	\
	fail_unless(strcmp((digest), cdigest) == 0, NULL); \
	\
	purple_cipher_context_destroy(context); \
}

START_TEST(test_sha256_empty_string) {
	SHA256_TEST("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
END_TEST

START_TEST(test_sha256_a) {
	SHA256_TEST("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
}
END_TEST

START_TEST(test_sha256_abc) {
	SHA256_TEST("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
END_TEST

START_TEST(test_sha256_abcd_gibberish) {
	SHA256_TEST("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}
END_TEST

START_TEST(test_sha256_1000_as_1000_times) {
	SHA256_TEST(NULL, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}
END_TEST

/******************************************************************************
 * DES Tests
 *****************************************************************************/
#define DES_TEST(in, keyz, out, len) { \
	PurpleCipher *cipher = NULL; \
	PurpleCipherContext *context = NULL; \
	guchar answer[len+1]; \
	gint ret = 0; \
	guchar decrypt[len+1] = in; \
	guchar key[8+1] = keyz;\
	guchar encrypt[len+1] = out;\
	size_t outlen; \
	\
	cipher = purple_ciphers_find_cipher("des"); \
	context = purple_cipher_context_new(cipher, NULL); \
	purple_cipher_context_set_key(context, key); \
	\
	ret = purple_cipher_context_encrypt(context, decrypt, len, answer, &outlen); \
	fail_unless(ret == 0, NULL); \
	fail_unless(outlen == (len), NULL); \
	fail_unless(memcmp(encrypt, answer, len) == 0, NULL); \
	\
	ret = purple_cipher_context_decrypt(context, encrypt, len, answer, &outlen); \
	fail_unless(ret == 0, NULL); \
	fail_unless(outlen == (len), NULL); \
	fail_unless(memcmp(decrypt, answer, len) == 0, NULL); \
	\
	purple_cipher_context_destroy(context); \
}

START_TEST(test_des_12345678) {
	DES_TEST("12345678",
	         "\x3b\x38\x98\x37\x15\x20\xf7\x5e",
	         "\x06\x22\x05\xac\x6a\x0d\x55\xdd",
	         8);
}
END_TEST

START_TEST(test_des_abcdefgh) {
	DES_TEST("abcdefgh",
	         "\x3b\x38\x98\x37\x15\x20\xf7\x5e",
	         "\x62\xe0\xc6\x8c\x48\xe4\x75\xed",
	         8);
}
END_TEST

/******************************************************************************
 * DES3 Tests
 * See http://csrc.nist.gov/groups/ST/toolkit/examples.html
 * and some NULL things I made up
 *****************************************************************************/

#define DES3_TEST(in, key, iv, out, len, mode) { \
	PurpleCipher *cipher = NULL; \
	PurpleCipherContext *context = NULL; \
	guchar answer[len+1]; \
	guchar decrypt[len+1] = in; \
	guchar encrypt[len+1] = out; \
	size_t outlen; \
	gint ret = 0; \
	\
	cipher = purple_ciphers_find_cipher("des3"); \
	context = purple_cipher_context_new(cipher, NULL); \
	purple_cipher_context_set_key(context, (guchar *)key); \
	purple_cipher_context_set_batch_mode(context, (mode)); \
	purple_cipher_context_set_iv(context, (guchar *)iv, 8); \
	\
	ret = purple_cipher_context_encrypt(context, decrypt, len, answer, &outlen); \
	fail_unless(ret == 0, NULL); \
	fail_unless(outlen == (len), NULL); \
	fail_unless(memcmp(encrypt, answer, len) == 0, NULL); \
	\
	ret = purple_cipher_context_decrypt(context, encrypt, len, answer, &outlen); \
	fail_unless(ret == 0, NULL); \
	fail_unless(outlen == (len), NULL); \
	fail_unless(memcmp(decrypt, answer, len) == 0, NULL); \
	\
	purple_cipher_context_destroy(context); \
}

START_TEST(test_des3_ecb_nist1) {
	DES3_TEST(
	          "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
	          "\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
	          "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
	          "\x23\x45\x67\x89\xAB\xCD\xEF\x01"
	          "\x45\x67\x89\xAB\xCD\xEF\x01\x23",
	          "00000000", /* ignored */
	          "\x71\x47\x72\xF3\x39\x84\x1D\x34\x26\x7F\xCC\x4B\xD2\x94\x9C\xC3"
	          "\xEE\x11\xC2\x2A\x57\x6A\x30\x38\x76\x18\x3F\x99\xC0\xB6\xDE\x87",
	          32,
	          PURPLE_CIPHER_BATCH_MODE_ECB);
}
END_TEST

START_TEST(test_des3_ecb_nist2) {
	DES3_TEST(
	          "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
	          "\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
	          "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
	          "\x23\x45\x67\x89\xAB\xCD\xEF\x01"
	          "\x01\x23\x45\x67\x89\xAB\xCD\xEF",
	          "00000000", /* ignored */
	          "\x06\xED\xE3\xD8\x28\x84\x09\x0A\xFF\x32\x2C\x19\xF0\x51\x84\x86"
	          "\x73\x05\x76\x97\x2A\x66\x6E\x58\xB6\xC8\x8C\xF1\x07\x34\x0D\x3D",
	          32,
	          PURPLE_CIPHER_BATCH_MODE_ECB);
}
END_TEST

START_TEST(test_des3_ecb_null_key) {
	DES3_TEST(
	          "\x16\xf4\xb3\x77\xfd\x4b\x9e\xca",
	          "\x38\x00\x88\x6a\xef\xcb\x00\xad"
	          "\x5d\xe5\x29\x00\x7d\x98\x64\x4c"
	          "\x86\x00\x7b\xd3\xc7\x00\x7b\x32",
	          "00000000", /* ignored */
	          "\xc0\x60\x30\xa1\xb7\x25\x42\x44",
	          8,
	          PURPLE_CIPHER_BATCH_MODE_ECB);
}
END_TEST

START_TEST(test_des3_ecb_null_text) {
	DES3_TEST(
	          "\x65\x73\x34\xc1\x19\x00\x79\x65",
	          "\x32\x64\xda\x10\x13\x6a\xfe\x1e"
	          "\x37\x54\xd1\x2c\x41\x04\x10\x40"
	          "\xaf\x1c\x75\x2b\x51\x3a\x03\xf5",
	          "00000000", /* ignored */
	          "\xe5\x80\xf6\x12\xf8\x4e\xd9\x6c",
	          8,
	          PURPLE_CIPHER_BATCH_MODE_ECB);
}
END_TEST

START_TEST(test_des3_ecb_null_key_and_text) {
	DES3_TEST(
	          "\xdf\x7f\x00\x92\xe7\xc1\x49\xd2",
	          "\x0e\x41\x00\xc4\x8b\xf0\x6e\xa1"
	          "\x66\x49\x42\x63\x22\x00\xf0\x99"
	          "\x6b\x22\xc1\x37\x9c\x00\xe4\x8f",
	          "00000000", /* ignored */
	          "\x73\xd8\x1f\x1f\x50\x01\xe4\x79",
	          8,
	          PURPLE_CIPHER_BATCH_MODE_ECB);
}
END_TEST

START_TEST(test_des3_cbc_nist1) {
	DES3_TEST(
	          "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
	          "\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
	          "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
	          "\x23\x45\x67\x89\xAB\xCD\xEF\x01"
	          "\x45\x67\x89\xAB\xCD\xEF\x01\x23",
	          "\xF6\x9F\x24\x45\xDF\x4F\x9B\x17",
	          "\x20\x79\xC3\xD5\x3A\xA7\x63\xE1\x93\xB7\x9E\x25\x69\xAB\x52\x62"
	          "\x51\x65\x70\x48\x1F\x25\xB5\x0F\x73\xC0\xBD\xA8\x5C\x8E\x0D\xA7",
	          32,
	          PURPLE_CIPHER_BATCH_MODE_CBC);
}
END_TEST

START_TEST(test_des3_cbc_nist2) {
	DES3_TEST(
	          "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
	          "\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
	          "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
	          "\x23\x45\x67\x89\xAB\xCD\xEF\x01"
	          "\x01\x23\x45\x67\x89\xAB\xCD\xEF",
	          "\xF6\x9F\x24\x45\xDF\x4F\x9B\x17",
	          "\x74\x01\xCE\x1E\xAB\x6D\x00\x3C\xAF\xF8\x4B\xF4\x7B\x36\xCC\x21"
	          "\x54\xF0\x23\x8F\x9F\xFE\xCD\x8F\x6A\xCF\x11\x83\x92\xB4\x55\x81",
	          32,
	          PURPLE_CIPHER_BATCH_MODE_CBC);
}
END_TEST

START_TEST(test_des3_cbc_null_key) {
	DES3_TEST(
	          "\x16\xf4\xb3\x77\xfd\x4b\x9e\xca",
	          "\x38\x00\x88\x6a\xef\xcb\x00\xad"
	          "\x5d\xe5\x29\x00\x7d\x98\x64\x4c"
	          "\x86\x00\x7b\xd3\xc7\x00\x7b\x32",
	          "\x31\x32\x33\x34\x35\x36\x37\x38",
	          "\x52\xe7\xde\x96\x39\x87\x87\xdb",
	          8,
	          PURPLE_CIPHER_BATCH_MODE_CBC);
}
END_TEST

START_TEST(test_des3_cbc_null_text) {
	DES3_TEST(
	          "\x65\x73\x34\xc1\x19\x00\x79\x65",
	          "\x32\x64\xda\x10\x13\x6a\xfe\x1e"
	          "\x37\x54\xd1\x2c\x41\x04\x10\x40"
	          "\xaf\x1c\x75\x2b\x51\x3a\x03\xf5",
	          "\x7C\xAF\x0D\x57\x1E\x57\x10\xDA",
	          "\x40\x12\x0e\x00\x85\xff\x6c\xc2",
	          8,
	          PURPLE_CIPHER_BATCH_MODE_CBC);
}
END_TEST

START_TEST(test_des3_cbc_null_key_and_text) {
	DES3_TEST(
	          "\xdf\x7f\x00\x92\xe7\xc1\x49\xd2",
	          "\x0e\x41\x00\xc4\x8b\xf0\x6e\xa1"
	          "\x66\x49\x42\x63\x22\x00\xf0\x99"
	          "\x6b\x22\xc1\x37\x9c\x00\xe4\x8f",
	          "\x01\x19\x0D\x2c\x40\x67\x89\x67",
	          "\xa7\xc1\x10\xbe\x9b\xd5\x8a\x67",
	          8,
	          PURPLE_CIPHER_BATCH_MODE_CBC);
}
END_TEST

/******************************************************************************
 * HMAC Tests
 * See RFC2202 and some other NULL tests I made up
 *****************************************************************************/

#define HMAC_TEST(data, data_len, key, key_len, type, digest) { \
	PurpleCipher *cipher = NULL; \
	PurpleCipherContext *context = NULL; \
	gchar cdigest[41]; \
	gboolean ret = FALSE; \
	\
	cipher = purple_ciphers_find_cipher("hmac"); \
	context = purple_cipher_context_new(cipher, NULL); \
	purple_cipher_context_set_option(context, "hash", type); \
	purple_cipher_context_set_key_with_len(context, (guchar *)key, (key_len)); \
	\
	purple_cipher_context_append(context, (guchar *)(data), (data_len)); \
	ret = purple_cipher_context_digest_to_str(context, sizeof(cdigest), cdigest, \
	                                        NULL); \
	\
	fail_unless(ret == TRUE, NULL); \
	fail_unless(strcmp((digest), cdigest) == 0, NULL); \
	\
	purple_cipher_context_destroy(context); \
}

/* HMAC MD5 */

START_TEST(test_hmac_md5_Hi) {
	HMAC_TEST("Hi There",
	          8,
	          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	          16,
	          "md5",
	          "9294727a3638bb1c13f48ef8158bfc9d");
}
END_TEST

START_TEST(test_hmac_md5_what) {
	HMAC_TEST("what do ya want for nothing?",
	          28,
	          "Jefe",
	          4,
	          "md5",
	          "750c783e6ab0b503eaa86e310a5db738");
}
END_TEST

START_TEST(test_hmac_md5_dd) {
	HMAC_TEST("\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
	          50,
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	          16,
	          "md5",
	          "56be34521d144c88dbb8c733f0e8b3f6");
}
END_TEST

START_TEST(test_hmac_md5_cd) {
	HMAC_TEST("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
	          50,
	          "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
	          "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
	          "\x15\x16\x17\x18\x19",
	          25,
	          "md5",
	          "697eaf0aca3a3aea3a75164746ffaa79");
}
END_TEST

START_TEST(test_hmac_md5_truncation) {
	HMAC_TEST("Test With Truncation",
	          20,
	          "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
	          16,
	          "md5",
	          "56461ef2342edc00f9bab995690efd4c");
}
END_TEST

START_TEST(test_hmac_md5_large_key) {
	HMAC_TEST("Test Using Larger Than Block-Size Key - Hash Key First",
	          54,
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	          80,
	          "md5",
	          "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
}
END_TEST

START_TEST(test_hmac_md5_large_key_and_data) {
	HMAC_TEST("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
	          73,
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	          80,
	          "md5",
	          "6f630fad67cda0ee1fb1f562db3aa53e");
}
END_TEST

START_TEST(test_hmac_md5_null_key) {
	HMAC_TEST("Hi There",
	          8,
	          "\x0a\x0b\x00\x0d\x0e\x0f\x1a\x2f\x0b\x0b"
	          "\x0b\x00\x00\x0b\x0b\x49\x5f\x6e\x0b\x0b",
	          20,
	          "md5",
	          "597bfd644b797a985561eeb03a169e59");
}
END_TEST

START_TEST(test_hmac_md5_null_text) {
	HMAC_TEST("Hi\x00There",
	          8,
	          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	          20,
	          "md5",
	          "70be8e1b7b50dfcc335d6cd7992c564f");
}
END_TEST

START_TEST(test_hmac_md5_null_key_and_text) {
	HMAC_TEST("Hi\x00Th\x00re",
	          8,
	          "\x0c\x0d\x00\x0f\x10\x1a\x3a\x3a\xe6\x34"
	          "\x0b\x00\x00\x0b\x0b\x49\x5f\x6e\x0b\x0b",
	          20,
	          "md5",
	          "b31bcbba35a33a067cbba9131cba4889");
}
END_TEST

/* HMAC SHA1 */

START_TEST(test_hmac_sha1_Hi) {
	HMAC_TEST("Hi There",
	          8,
	          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	          20,
	          "sha1",
	          "b617318655057264e28bc0b6fb378c8ef146be00");
}
END_TEST

START_TEST(test_hmac_sha1_what) {
	HMAC_TEST("what do ya want for nothing?",
	          28,
	          "Jefe",
	          4,
	          "sha1",
	          "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}
END_TEST

START_TEST(test_hmac_sha1_dd) {
	HMAC_TEST("\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	          "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
	          50,
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	          20,
	          "sha1",
	          "125d7342b9ac11cd91a39af48aa17b4f63f175d3");
}
END_TEST

START_TEST(test_hmac_sha1_cd) {
	HMAC_TEST("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
	          50,
	          "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
	          "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
	          "\x15\x16\x17\x18\x19",
	          25,
	          "sha1",
	          "4c9007f4026250c6bc8414f9bf50c86c2d7235da");
}
END_TEST

START_TEST(test_hmac_sha1_truncation) {
	HMAC_TEST("Test With Truncation",
	          20,
	          "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
	          "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
	          20,
	          "sha1",
	          "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04");
}
END_TEST

START_TEST(test_hmac_sha1_large_key) {
	HMAC_TEST("Test Using Larger Than Block-Size Key - Hash Key First",
	          54,
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	          80,
	          "sha1",
	          "aa4ae5e15272d00e95705637ce8a3b55ed402112");
}
END_TEST

START_TEST(test_hmac_sha1_large_key_and_data) {
	HMAC_TEST("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
	          73,
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	          "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	          80,
	          "sha1",
	          "e8e99d0f45237d786d6bbaa7965c7808bbff1a91");
}
END_TEST

START_TEST(test_hmac_sha1_null_key) {
	HMAC_TEST("Hi There",
	          8,
	          "\x0a\x0b\x00\x0d\x0e\x0f\x1a\x2f\x0b\x0b"
	          "\x0b\x00\x00\x0b\x0b\x49\x5f\x6e\x0b\x0b",
	          20,
	          "sha1",
	          "eb62a2e0e33d300be669c52aab3f591bc960aac5");
}
END_TEST

START_TEST(test_hmac_sha1_null_text) {
	HMAC_TEST("Hi\x00There",
	          8,
	          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	          20,
	          "sha1",
	          "31ca58d849e971e418e3439de2c6f83144b6abb7");
}
END_TEST

START_TEST(test_hmac_sha1_null_key_and_text) {
	HMAC_TEST("Hi\x00Th\x00re",
	          8,
	          "\x0c\x0d\x00\x0f\x10\x1a\x3a\x3a\xe6\x34"
	          "\x0b\x00\x00\x0b\x0b\x49\x5f\x6e\x0b\x0b",
	          20,
	          "sha1",
	          "e6b8e2fede87aa09dcb13e554df1435e056eae36");
}
END_TEST

/******************************************************************************
 * Suite
 *****************************************************************************/
Suite *
cipher_suite(void) {
	Suite *s = suite_create("Cipher Suite");
	TCase *tc = NULL;

	/* md4 tests */
	tc = tcase_create("MD4");
	tcase_add_test(tc, test_md4_empty_string);
	tcase_add_test(tc, test_md4_a);
	tcase_add_test(tc, test_md4_abc);
	tcase_add_test(tc, test_md4_message_digest);
	tcase_add_test(tc, test_md4_a_to_z);
	tcase_add_test(tc, test_md4_A_to_Z_a_to_z_0_to_9);
	tcase_add_test(tc, test_md4_1_to_0_8_times);
	suite_add_tcase(s, tc);

	/* md5 tests */
	tc = tcase_create("MD5");
	tcase_add_test(tc, test_md5_empty_string);
	tcase_add_test(tc, test_md5_a);
	tcase_add_test(tc, test_md5_abc);
	tcase_add_test(tc, test_md5_message_digest);
	tcase_add_test(tc, test_md5_a_to_z);
	tcase_add_test(tc, test_md5_A_to_Z_a_to_z_0_to_9);
	tcase_add_test(tc, test_md5_1_to_0_8_times);
	suite_add_tcase(s, tc);

	/* sha1 tests */
	tc = tcase_create("SHA1");
	tcase_add_test(tc, test_sha1_empty_string);
	tcase_add_test(tc, test_sha1_a);
	tcase_add_test(tc, test_sha1_abc);
	tcase_add_test(tc, test_sha1_abcd_gibberish);
	tcase_add_test(tc, test_sha1_1000_as_1000_times);
	suite_add_tcase(s, tc);

	/* sha256 tests */
	tc = tcase_create("SHA256");
	tcase_add_test(tc, test_sha256_empty_string);
	tcase_add_test(tc, test_sha256_a);
	tcase_add_test(tc, test_sha256_abc);
	tcase_add_test(tc, test_sha256_abcd_gibberish);
	tcase_add_test(tc, test_sha256_1000_as_1000_times);
	suite_add_tcase(s, tc);

	/* des tests */
	tc = tcase_create("DES");
	tcase_add_test(tc, test_des_12345678);
	tcase_add_test(tc, test_des_abcdefgh);
	suite_add_tcase(s, tc);

	/* des3 ecb tests */
	tc = tcase_create("DES3 ECB");
	tcase_add_test(tc, test_des3_ecb_nist1);
	tcase_add_test(tc, test_des3_ecb_nist2);
	tcase_add_test(tc, test_des3_ecb_null_key);
	tcase_add_test(tc, test_des3_ecb_null_text);
	tcase_add_test(tc, test_des3_ecb_null_key_and_text);
	suite_add_tcase(s, tc);
	/* des3 cbc tests */
	tc = tcase_create("DES3 CBC");
	tcase_add_test(tc, test_des3_cbc_nist1);
	tcase_add_test(tc, test_des3_cbc_nist2);
	tcase_add_test(tc, test_des3_cbc_null_key);
	tcase_add_test(tc, test_des3_cbc_null_text);
	tcase_add_test(tc, test_des3_cbc_null_key_and_text);
	suite_add_tcase(s, tc);

	/* hmac tests */
	tc = tcase_create("HMAC");
	tcase_add_test(tc, test_hmac_md5_Hi);
	tcase_add_test(tc, test_hmac_md5_what);
	tcase_add_test(tc, test_hmac_md5_dd);
	tcase_add_test(tc, test_hmac_md5_cd);
	tcase_add_test(tc, test_hmac_md5_truncation);
	tcase_add_test(tc, test_hmac_md5_large_key);
	tcase_add_test(tc, test_hmac_md5_large_key_and_data);
	tcase_add_test(tc, test_hmac_md5_null_key);
	tcase_add_test(tc, test_hmac_md5_null_text);
	tcase_add_test(tc, test_hmac_md5_null_key_and_text);
	tcase_add_test(tc, test_hmac_sha1_Hi);
	tcase_add_test(tc, test_hmac_sha1_what);
	tcase_add_test(tc, test_hmac_sha1_dd);
	tcase_add_test(tc, test_hmac_sha1_cd);
	tcase_add_test(tc, test_hmac_sha1_truncation);
	tcase_add_test(tc, test_hmac_sha1_large_key);
	tcase_add_test(tc, test_hmac_sha1_large_key_and_data);
	tcase_add_test(tc, test_hmac_sha1_null_key);
	tcase_add_test(tc, test_hmac_sha1_null_text);
	tcase_add_test(tc, test_hmac_sha1_null_key_and_text);
	suite_add_tcase(s, tc);

	return s;
}


