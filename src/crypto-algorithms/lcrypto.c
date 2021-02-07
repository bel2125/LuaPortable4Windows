#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#define strdup _strdup
#endif

#include "lua_all.h"
#include "base64.h"
#include "blowfish.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "rot-13.h"


static int lua_base64_encode(lua_State *L)
{
	int newline = 0;

	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (lua_type(L, 2) == LUA_TBOOLEAN) {
		newline = lua_toboolean(L, 2);
	}
	else if ((lua_type(L, 2) != LUA_TNONE) && (lua_type(L, 2) != LUA_TNIL)) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	size_t out_len = base64_encode(in, NULL, in_len, newline);
	char * out = malloc(out_len + 1);
	if (out == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	size_t out_len2 = base64_encode(in, out, in_len, newline);
	if (out_len != out_len2) {
		return luaL_error(L, "%s consistency error", __func__);
	}
	lua_pushlstring(L, out, out_len);
	free(out);
	return 1;
}


static int lua_base64_decode(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	size_t out_len = base64_decode(in, NULL, in_len);
	char * out = malloc(out_len + 1);
	if (out == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	size_t out_len2 = base64_decode(in, out, in_len);
	if (out_len != out_len2) {
		return luaL_error(L, "%s consistency error", __func__);
	}
	lua_pushlstring(L, out, out_len);
	free(out);
	return 1;
}


static int lua_blowfish_preparekey(lua_State *L)
{
	int newline = 0;

	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t key_len = 0;
	const char *key = lua_tolstring(L, 1, &key_len);

	BLOWFISH_KEY *pkeystruct = (BLOWFISH_KEY *)lua_newuserdata(L, sizeof(BLOWFISH_KEY));
	if (pkeystruct == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	lua_pushlightuserdata(L, &lua_blowfish_preparekey);
	lua_setuservalue(L, -2);
	blowfish_key_setup(key, pkeystruct, key_len);
	return 1;
}


static int lua_blowfish_encrypt(lua_State *L)
{
	int newline = 0;

	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (lua_type(L, 2) != LUA_TUSERDATA) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_getuservalue(L, 2);
	if (lua_type(L, -1) != LUA_TLIGHTUSERDATA) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	void *p = lua_touserdata(L, -1);
	if (p != (void*)lua_blowfish_preparekey) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	BLOWFISH_KEY *pkeystruct = (BLOWFISH_KEY *)lua_touserdata(L, -1);
	char out[8];
	blowfish_encrypt(in, out, pkeystruct);
	lua_pushlstring(L, out, 8);
	return 1;
}




static int lua_rot13(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	const char *in = lua_tostring(L, 1);
	char *out = strdup(in);
	if (out == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	rot13(out);
	lua_pushstring(L, out);
	free(out);
	return 1;
}


static char tohex(unsigned char c, int upper)
{
	if (c < 10) return c + '0';
	if (upper) return c + 'A' - 10;
	return c + 'a' - 10;
}


static unsigned char fromhex(char c)
{
	if ((c >= '0') && (c <= '9')) return c - '0';
	if ((c >= 'A') && (c <= 'F')) return c - 'A' + 10;
	if ((c >= 'a') && (c <= 'f')) return c - 'a' + 10;
	return 255;
}


static int lua_hex_encode(lua_State *L)
{
	int upper = 1;

	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (lua_type(L, 2) == LUA_TBOOLEAN) {
		upper = lua_toboolean(L, 2);
	}
	else if ((lua_type(L, 2) != LUA_TNONE) && (lua_type(L, 2) != LUA_TNIL)) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	size_t out_len = in_len * 2;
	char * out = malloc(out_len + 1);
	if (out == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}

	for (size_t i = 0; i < in_len; i++) {
		out[2 * i + 0] = tohex(((unsigned char)in[i]) >> 4, upper);
		out[2 * i + 1] = tohex(((unsigned char)in[i]) & 0x0F, upper);
	}


	lua_pushlstring(L, out, out_len);
	free(out);
	return 1;
}


static int lua_hex_decode(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	if ((in_len % 2) != 0) {
		return luaL_error(L, "%s input error", __func__);
	}

	size_t out_len = in_len / 2;
	char * out = malloc(out_len + 1);
	if (out == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}

	for (size_t i = 0; i < out_len; i++) {
		unsigned char c1 = fromhex(in[2 * i]);
		unsigned char c2 = fromhex(in[2 * i + 1]);
		if ((c1 > 15) || (c2 > 15)) {
			return luaL_error(L, "%s input error", __func__);
		}
		out[i] = (char)((c1 << 4) + c2);
	}


	lua_pushlstring(L, out, out_len);
	free(out);
	return 1;
}


static uint16_t crc16table[256];
static uint32_t crc32table[256];

static void init_crc_tables()
{
	for (int i = 0; i<256; i++) {
		uint8_t c = (uint8_t)i;
		uint16_t crc16 = 0;
		uint32_t crc32 = (uint32_t)i;
		for (int j = 0; j < 8; j++, c >>= 1) {
			crc16 = (((crc16 ^ (uint16_t)c) & 1) == 1) ? ((crc16 >> 1) ^ 0xA001) : (crc16 >> 1);
			crc32 = ((crc32 & 1) == 1) ? ((crc32 >> 1) ^ (uint32_t)0xEDB88320ul) : (crc32 >> 1);
		}
		crc16table[i] = crc16;
		crc32table[i] = crc32;
	}
}


static int lua_crc16(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	uint16_t crc16 = 0;
	for (size_t i = 0; i < in_len; i++) {
		crc16 = (crc16 >> 8) ^ crc16table[(crc16 ^ (uint16_t)in[i]) & (uint32_t)0xFF];
	}

	char buf[2];
	buf[0] = (char)(crc16 >> 8);
	buf[1] = (char)(crc16 & 0xFF);
	lua_pushlstring(L, buf, 2);
	return 1;
}


static int lua_crc32(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	uint32_t crc32 = 0xFFFFFFFFul;
	for (size_t i = 0; i < in_len; i++) {
		crc32 = (crc32 >> 8) ^ crc32table[(crc32 ^ (uint32_t)in[i]) & (uint32_t)0xFF];
	}

	crc32 ^= 0xFFFFFFFFul;

	char buf[4];
	buf[0] = (char)(crc32 >> 24);
	buf[1] = (char)((crc32 >> 16) & 0xFF);
	buf[2] = (char)((crc32 >> 8) & 0xFF);
	buf[3] = (char)(crc32 & 0xFF);
	lua_pushlstring(L, buf, 4);
	return 1;
}


static int lua_md2(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	BYTE buf[MD2_BLOCK_SIZE];
	MD2_CTX ctx;

	md2_init(&ctx);
	md2_update(&ctx, in, in_len);
	md2_final(&ctx, buf);

	lua_pushlstring(L, buf, 16);
	return 1;
}


static int lua_md5(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	BYTE buf[MD5_BLOCK_SIZE];
	MD5_CTX ctx;

	md5_init(&ctx);
	md5_update(&ctx, in, in_len);
	md5_final(&ctx, buf);

	lua_pushlstring(L, buf, MD5_BLOCK_SIZE);
	return 1;
}


static int lua_sha1(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	BYTE buf[SHA1_BLOCK_SIZE];
	SHA1_CTX ctx;

	sha1_init(&ctx);
	sha1_update(&ctx, in, in_len);
	sha1_final(&ctx, buf);

	lua_pushlstring(L, buf, SHA1_BLOCK_SIZE);
	return 1;
}


static int lua_sha256(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, in, in_len);
	sha256_final(&ctx, buf);

	lua_pushlstring(L, buf, SHA256_BLOCK_SIZE);
	return 1;
}


static const struct luaL_Reg funclist[] = {
	{ "base64_encode", lua_base64_encode },
	{ "base64_decode", lua_base64_decode },
	{ "hex_encode", lua_hex_encode },
	{ "hex_decode", lua_hex_decode },

	{ "blowfish_preparekey", lua_blowfish_preparekey },
	{ "blowfish_encrypt", lua_blowfish_encrypt },

	{ "crc16", lua_crc16 },
	{ "crc32", lua_crc32 },
	{ "md2", lua_md2 },
	{ "md5", lua_md5 },
	{ "sha1", lua_sha1 },
	{ "sha256", lua_sha256 },
	{ "rot13", lua_rot13 },

	{ NULL, NULL },
};


int luaopen_crypto(lua_State *L)
{
	init_crc_tables();
	luaL_newlib(L, funclist);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "crypto");
	return 1;
}
