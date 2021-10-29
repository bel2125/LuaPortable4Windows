#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#define strdup _strdup
#define stricmp _stricmp
#endif

#include "lua_all.h"

#include "aes.h"
#include "arcfour.h"
#include "base64.h"
#include "blowfish.h"
#include "des.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "sha-2.h"
//#include "sha256.h"
#include "rot-13.h"

static const char * mode_names[] = { "EBC", "CBC", "PCBC", "CFB", "OFB", "CTR", "CTR-LE" };
enum cyphermode { mode_ECB = 0, mode_CBC, mode_PCBC, mode_CFB, mode_OFB, mode_CTR, mode_CTR_LE, mode_enum_count };

typedef struct tEncDecFunc {
	void(*Encrypt)(uint8_t *dst, uint8_t *src, void *sched);
	void(*Decrypt)(uint8_t *dst, uint8_t *src, void *sched);
} FUNC;

typedef struct tBlockCipherBase {
	FUNC func;
	uint16_t bit_size;
	uint8_t byte_size;
	uint8_t can_encode;
	uint8_t can_decode;
	enum cyphermode mode;
	uint8_t init_vector[128];
	uint8_t counter[128];
} BLOCKCYPHERBASE;

typedef struct tL_AES_KEY {
	BLOCKCYPHERBASE block;
	uint64_t schedule[60];
} L_AES_KEY;

typedef struct tL_DES_KEY {
	BLOCKCYPHERBASE block;
	BYTE schedule[3][16][6];
	BYTE isThree;
} L_DES_KEY;

typedef struct tL_BLOWFISH_KEY {
	BLOCKCYPHERBASE block;
	BLOWFISH_KEY schedule;
} L_BLOWFISH_KEY;

typedef struct tL_RC4_KEY {
	BYTE schedule[256];
} L_RC4_KEY;


static void Encrypt_AES(uint8_t *dst, uint8_t *src, void *sched)
{
	L_AES_KEY *k = (L_AES_KEY*)sched;
	aes_encrypt(src, dst, k->schedule, k->block.bit_size);
}


static void Decrypt_AES(uint8_t *dst, uint8_t *src, void *sched)
{
	L_AES_KEY *k = (L_AES_KEY*)sched;
	aes_decrypt(src, dst, k->schedule, k->block.bit_size);
}


static void Encrypt_BLOWFISH(uint8_t *dst, uint8_t *src, void *sched)
{
	L_BLOWFISH_KEY *k = (L_BLOWFISH_KEY*)sched;
	blowfish_encrypt(src, dst, &(k->schedule));
}


static void Decrypt_BLOWFISH(uint8_t *dst, uint8_t *src, void *sched)
{
	L_BLOWFISH_KEY *k = (L_BLOWFISH_KEY*)sched;
	blowfish_decrypt(src, dst, &(k->schedule));
}


static void Encrypt_DES(uint8_t *dst, uint8_t *src, void *sched)
{
	L_DES_KEY *k = (L_DES_KEY*)sched;
	if (k->isThree) {
		three_des_crypt(src, dst, &(k->schedule));
	} else {
		des_crypt(src, dst, &(k->schedule));
	}
}


static void Decrypt_DES(uint8_t *dst, uint8_t *src, void *sched)
{
	L_DES_KEY *k = (L_DES_KEY*)sched;
	if (k->isThree) {
		three_des_crypt(src, dst, &(k->schedule));
	}
	else {
		des_crypt(src, dst, &(k->schedule));
	}
}


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
		free(out);
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
		free(out);
		return luaL_error(L, "%s consistency error", __func__);
	}
	lua_pushlstring(L, out, out_len);
	free(out);
	return 1;
}


static void memxor(uint8_t *inout, const uint8_t * xor, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		inout[i] = inout[i] ^ xor[i];
	}
}


static void counter_inc_le(uint8_t *inout, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		inout[i]++;
		if (inout[i]) break;
	}
}


static void counter_inc_be(uint8_t *inout, size_t len)
{
	for (size_t i = len; i > 0; i--) {
		inout[i-1]++;
		if (inout[i-1]) break;
	}
}


void Block_Encrypt(BLOCKCYPHERBASE *block, void *prm, uint8_t *data, size_t len)
{
	uint8_t savevec[256];
	size_t b = block->byte_size;

	switch (block->mode) {
	case mode_CBC:
		for (size_t i = 0; i < len; i += b) {
			memxor(data + i, block->init_vector, b);
			block->func.Encrypt(data + i, data + i, prm);
			memcpy(block->init_vector, data + i, b);
		}
		break;
	case mode_PCBC:
		for (size_t i = 0; i < len; i += b) {
			memcpy(savevec, data + i, b);
			memxor(block->init_vector, data + i, b);
			block->func.Encrypt(data + i, block->init_vector, prm);
			memxor(savevec, data + i, b);
			memcpy(block->init_vector, savevec, b);
		}
		break;
	case mode_CFB:
		for (size_t i = 0; i < len; i += b) {
			block->func.Encrypt(block->init_vector, block->init_vector, prm);
			memxor(data + i, block->init_vector, b);
			memcpy(block->init_vector, data + i, b);
		}
		break;
	case mode_OFB:
		for (size_t i = 0; i < len; i += b) {
			block->func.Encrypt(block->init_vector, block->init_vector, prm);
			memxor(data + i, block->init_vector, b);
		}
		break;
	case mode_CTR:
		for (size_t i = 0; i < len; i += b) {
			memcpy(savevec, block->counter, b);
			memxor(savevec, block->init_vector, b);
			block->func.Encrypt(savevec, savevec, prm);
			memxor(data + i, savevec, b);
			counter_inc_be(block->counter, b);
		}
		break;
	default:
		for (size_t i = 0; i < len; i += b) {
			block->func.Encrypt(data + i, data + i, prm);
		}
	}
}


void Block_Decrypt(BLOCKCYPHERBASE *block, void *prm, uint8_t *data, size_t len)
{
	uint8_t savevec[256];
	size_t b = block->byte_size;

	switch (block->mode) {
	case mode_CBC:
		for (size_t i = 0; i < len; i += b) {
			memcpy(savevec, block->init_vector, b);
			memcpy(block->init_vector, data + i, b);
			block->func.Decrypt(data + i, data + i, prm);
			memxor(data + i, savevec, b);
		}
		break;

	case mode_PCBC:
		for (size_t i = 0; i < len; i += b) {
			memcpy(savevec, data + i, b);
			block->func.Decrypt(data + i, data + i, prm);
			memxor(data + i, block->init_vector, b);
			memxor(savevec, data + i, b);
			memcpy(block->init_vector, savevec, b);
		}
		break;
	case mode_CFB:
		for (size_t i = 0; i < len; i += b) {
			/* use ENCRYPT, not DECRYPT here */
			block->func.Encrypt(savevec, block->init_vector, prm);
			memcpy(block->init_vector, data + i, b);
			memxor(data + i, savevec, b);
		}
		break;
	case mode_OFB:
		for (size_t i = 0; i < len; i += b) {
			/* use ENCRYPT, not DECRYPT here */
			block->func.Encrypt(block->init_vector, block->init_vector, prm);
			memxor(data + i, block->init_vector, b);
		}
		break;
	case mode_CTR:
		for (size_t i = 0; i < len; i += b) {
			memcpy(savevec, block->counter, b);
			memxor(savevec, block->init_vector, b);
			/* use ENCRYPT, not DECRYPT here */
			block->func.Encrypt(savevec, savevec, prm);
			memxor(data + i, savevec, b);
			counter_inc_be(block->counter, b);
		}
		break;
	default:
		for (size_t i = 0; i < len; i += b) {
			block->func.Decrypt(data + i, data + i, prm);
		}
	}
}


static int lua_aes_prepare_key(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (lua_type(L, 2) != LUA_TNUMBER) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t key_len = 0;
	const char *key = lua_tolstring(L, 1, &key_len);
	int key_len_bits = (int)key_len * 8;

	double arg2 = lua_tonumber(L, 2);

	if ((arg2 != 128) && (arg2 != 192) && (arg2 != 256)) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	if (arg2 < key_len_bits) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	key_len_bits = (int)arg2;

	L_AES_KEY *pkeystruct = (L_AES_KEY *)lua_newuserdata(L, sizeof(L_AES_KEY));
	if (pkeystruct == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	lua_pushlightuserdata(L, &lua_aes_prepare_key);
	lua_setuservalue(L, -2);

	memset(pkeystruct, 0, sizeof(L_AES_KEY));
	pkeystruct->block.func.Encrypt = Encrypt_AES;
	pkeystruct->block.func.Decrypt = Decrypt_AES;
	pkeystruct->block.bit_size = key_len_bits;
	pkeystruct->block.byte_size = key_len_bits/8;
	pkeystruct->block.can_encode = 1;
	pkeystruct->block.can_decode = 1;

	char key32[32];
	memset(key32, 0, sizeof(key32));
	memcpy(key32, key, key_len);
	aes_key_setup(key32, pkeystruct->schedule, key_len_bits);
	return 1;
}


static int lua_aes_encrypt(lua_State *L)
{
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
	if (p != (void*)lua_aes_prepare_key) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	L_AES_KEY *pkeystruct = (L_AES_KEY *)lua_touserdata(L, 2);

	int b = pkeystruct->block.byte_size;
	in_len = ((in_len + (b - 1)) / b) * b;
	char *data = calloc(in_len + b + 1, 1);
	if (data == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	memcpy(data, in, in_len);

	Block_Encrypt(&pkeystruct->block, pkeystruct, data, in_len);
	lua_pushlstring(L, data, in_len);
	free(data);
	return 1;
}


static int lua_aes_decrypt(lua_State *L)
{
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
	if (p != (void*)lua_aes_prepare_key) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	L_AES_KEY *pkeystruct = (L_AES_KEY *)lua_touserdata(L, 2);

	int b = pkeystruct->block.byte_size;
	in_len = ((in_len + (b - 1)) / b) * b;
	char *data = calloc(in_len + b + 1, 1);
	if (data == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	memcpy(data, in, in_len);

	Block_Decrypt(&pkeystruct->block, pkeystruct, data, in_len);
	lua_pushlstring(L, data, in_len);
	free(data);
	return 1;
}


static int lua_blowfish_prepare_key(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t key_len = 0;
	const char *key = lua_tolstring(L, 1, &key_len);

	L_BLOWFISH_KEY *pkeystruct = (L_BLOWFISH_KEY *)lua_newuserdata(L, sizeof(L_BLOWFISH_KEY));
	if (pkeystruct == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	lua_pushlightuserdata(L, &lua_blowfish_prepare_key);
	lua_setuservalue(L, -2);

	memset(pkeystruct, 0, sizeof(L_BLOWFISH_KEY));
	pkeystruct->block.func.Encrypt = Encrypt_BLOWFISH;
	pkeystruct->block.func.Decrypt = Decrypt_BLOWFISH;
	pkeystruct->block.bit_size = 64;
	pkeystruct->block.byte_size = 64 / 8;
	pkeystruct->block.can_encode = 1;
	pkeystruct->block.can_decode = 1;
	blowfish_key_setup(key, &(pkeystruct->schedule), key_len);

	return 1; 
}


static int lua_blowfish_encrypt(lua_State *L)
{
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
	if (p != (void*)lua_blowfish_prepare_key) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	L_BLOWFISH_KEY *pkeystruct = (L_BLOWFISH_KEY *)lua_touserdata(L, 2);

	int b = pkeystruct->block.byte_size;
	in_len = ((in_len + (b - 1)) / b) * b;
	char *data = calloc(in_len + b + 1, 1);
	if (data == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	memcpy(data, in, in_len);

	Block_Encrypt(&pkeystruct->block, pkeystruct, data, in_len);
	lua_pushlstring(L, data, in_len);
	free(data);
	return 1;
}


static int lua_blowfish_decrypt(lua_State *L)
{
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
	if (p != (void*)lua_blowfish_prepare_key) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	L_BLOWFISH_KEY *pkeystruct = (L_BLOWFISH_KEY *)lua_touserdata(L, 2);

	int b = pkeystruct->block.byte_size;
	in_len = ((in_len + (b - 1)) / b) * b;
	char *data = calloc(in_len + b + 1, 1);
	if (data == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	memcpy(data, in, in_len);

	Block_Decrypt(&pkeystruct->block, pkeystruct, data, in_len);
	lua_pushlstring(L, data, in_len);
	free(data);
	return 1;
}


static int lua_rc4_prepare_key(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t key_len = 0;
	const char *key = lua_tolstring(L, 1, &key_len);

	L_RC4_KEY *pkeystruct = (L_RC4_KEY *)lua_newuserdata(L, sizeof(L_RC4_KEY));
	if (pkeystruct == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	lua_pushlightuserdata(L, &lua_rc4_prepare_key);
	lua_setuservalue(L, -2);

	memset(pkeystruct, 0, sizeof(L_RC4_KEY));
	arcfour_key_setup(pkeystruct->schedule, key, key_len);
	return 1;
}


static int lua_rc4(lua_State *L)
{
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
	if (p != (void*)lua_rc4_prepare_key) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	L_RC4_KEY *pkeystruct = (L_RC4_KEY *)lua_touserdata(L, 2);

	char *data = malloc(in_len + 1);
	if (data == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}

	arcfour_generate_stream(pkeystruct->schedule, data, in_len);
	memxor(data, in, in_len);
	lua_pushlstring(L, data, in_len);
	free(data);
	return 1;
}


static int lua_des_prepare_key(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (lua_type(L, 2) != LUA_TBOOLEAN) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (lua_type(L, 3) != LUA_TBOOLEAN) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t key_len = 0;
	const char *key = lua_tolstring(L, 1, &key_len);

	int encrypt = lua_toboolean(L, 2);
	int use3DES = lua_toboolean(L, 3);

	if (key_len < 1) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (use3DES && (key_len > 24)) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (!use3DES && (key_len > 8)) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	L_DES_KEY *pkeystruct = (L_DES_KEY *)lua_newuserdata(L, sizeof(L_DES_KEY));
	if (pkeystruct == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	lua_pushlightuserdata(L, &lua_des_prepare_key);
	lua_setuservalue(L, -2);

	memset(pkeystruct, 0, sizeof(L_DES_KEY));
	pkeystruct->block.func.Encrypt = Encrypt_DES;
	pkeystruct->block.func.Decrypt = Decrypt_DES;
	pkeystruct->block.bit_size = 64;
	pkeystruct->block.byte_size = 64 / 8;
	pkeystruct->block.can_encode = !!encrypt;
	pkeystruct->block.can_decode = !encrypt;
	pkeystruct->isThree = !!use3DES;

	if (use3DES) {
		char key24[24];
		memset(key24, 0, sizeof(key24));
		memcpy(key24, key, key_len);
		three_des_key_setup(key24, pkeystruct->schedule, encrypt ? DES_ENCRYPT : DES_DECRYPT);
	} else {
		char key8[8];
		memset(key8, 0, sizeof(key8));
		memcpy(key8, key, key_len);
		des_key_setup(key8, pkeystruct->schedule, encrypt ? DES_ENCRYPT : DES_DECRYPT);
	}
	return 1;
}


static int lua_des(lua_State *L, int encrypt)
{
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
	if (p != (void*)lua_des_prepare_key) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);
	L_DES_KEY *pkeystruct = (L_DES_KEY *)lua_touserdata(L, 2);

	int b = pkeystruct->block.byte_size;
	in_len = ((in_len + (b - 1)) / b) * b;
	char *data = calloc(in_len + b + 1, 1);
	if (data == NULL) {
		return luaL_error(L, "%s out of memory", __func__);
	}
	memcpy(data, in, in_len);

	if (encrypt) Block_Encrypt(&pkeystruct->block, pkeystruct, data, in_len);
	else Block_Decrypt(&pkeystruct->block, pkeystruct, data, in_len);
	lua_pushlstring(L, data, in_len);
	free(data);
	return 1;
}


static int lua_des_encrypt(lua_State *L)
{
	return lua_des(L, 1);
}


static int lua_des_decrypt(lua_State *L)
{
	return lua_des(L, 0);
}


static int lua_set_cipher_mode(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TUSERDATA) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	if (lua_type(L, 2) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_getuservalue(L, 1);
	if (lua_type(L, -1) != LUA_TLIGHTUSERDATA) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	void *p = lua_touserdata(L, -1);
	if ((p != (void*)lua_aes_prepare_key) && (p != (void*)lua_blowfish_prepare_key) && (p != (void*)lua_des_prepare_key)) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_pop(L, 1);

	BLOCKCYPHERBASE *pblock = (BLOCKCYPHERBASE *)lua_touserdata(L, 1);
	const char *mode = lua_tostring(L, 2);

	if (0 == stricmp(mode, "ECB")) {
		memset(pblock->init_vector, 0, sizeof(pblock->init_vector));
		memset(pblock->counter, 0, sizeof(pblock->counter));
		pblock->mode = mode_ECB;
		lua_pushboolean(L, 1);
		return 1;
	}

	if (lua_type(L, 3) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	static vec_len = 0;
	const char *vec = lua_tolstring(L, 3, &vec_len);
	if (vec_len != pblock->byte_size) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	int found_mode = -1;
	for (int i = 0; i < mode_enum_count; i++) {
		if (0 == stricmp(mode, mode_names[i])) {
			found_mode = i;
			break;
		}
	}
	if (found_mode < 0) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	memset(pblock->init_vector, 0, sizeof(pblock->init_vector));
	memset(pblock->counter, 0, sizeof(pblock->counter));
	memcpy(pblock->init_vector, vec, vec_len);
	pblock->mode = found_mode;
	lua_pushboolean(L, 1);
	return 1;
}


static int lua_get_cipher_info(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TUSERDATA) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	lua_getuservalue(L, 1);
	if (lua_type(L, -1) != LUA_TLIGHTUSERDATA) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	void *p = lua_touserdata(L, -1);
	lua_pop(L, 1);

	// all stream ciphers
	if (p == (void*)lua_rc4_prepare_key) {
		lua_newtable(L);
		lua_pushstring(L, "cipher");
		lua_pushstring(L, "aes");
		lua_rawset(L, -3);
		lua_pushstring(L, "stream");
		lua_pushboolean(L, 1);
		lua_rawset(L, -3);
		return 1;
	}

	// all block ciphers
	if (p == (void*)lua_aes_prepare_key) {
		lua_newtable(L);
		lua_pushstring(L, "cipher");
		lua_pushstring(L, "AES");
		lua_rawset(L, -3);
	}
	else if (p == (void*)lua_blowfish_prepare_key) {
		lua_newtable(L);
		lua_pushstring(L, "cipher");
		lua_pushstring(L, "BLOWFISH");
		lua_rawset(L, -3);
	}
	else if (p == (void*)lua_des_prepare_key) {
		L_DES_KEY *pkeystruct = (L_DES_KEY *)lua_touserdata(L, 1);
		lua_newtable(L);
		lua_pushstring(L, "cipher");
		if (pkeystruct->isThree) {
			lua_pushstring(L, "3DES");
		}
		else {
			lua_pushstring(L, "DES");
		}
		lua_rawset(L, -3);
	}
	else {
		return luaL_error(L, "%s parameter error", __func__);
	}

	lua_pushstring(L, "block");
	lua_pushboolean(L, 1);
	lua_rawset(L, -3);

	BLOCKCYPHERBASE *pblock = (BLOCKCYPHERBASE *)lua_touserdata(L, 1); /* do not use pblock before p is checked */

	lua_pushstring(L, "encode");
	lua_pushboolean(L, pblock->can_encode);
	lua_rawset(L, -3);
	lua_pushstring(L, "decode");
	lua_pushboolean(L, pblock->can_decode);
	lua_rawset(L, -3);
	lua_pushstring(L, "bit_size");
	lua_pushinteger(L, pblock->bit_size);
	lua_rawset(L, -3);
	lua_pushstring(L, "byte_size");
	lua_pushinteger(L, pblock->byte_size);
	lua_rawset(L, -3);
	if ((pblock->mode < 0) || (pblock->mode >= mode_enum_count)) {
		pblock->mode = 0;
	}
	lua_pushstring(L, "mode");
	lua_pushstring(L, mode_names[pblock->mode]);
	lua_rawset(L, -3);

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


static int lua_sha224(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

    BYTE buf[224/8];
	struct sha224_state ctx;

	sha224_init(&ctx);
	sha224_process(&ctx, in, in_len);
	sha224_done(&ctx, buf);

	lua_pushlstring(L, buf, sizeof(buf));
	return 1;
}


static int lua_sha256(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

    BYTE buf[256/8];
	struct sha256_state ctx;

	sha256_init(&ctx);
	sha256_process(&ctx, in, in_len);
	sha256_done(&ctx, buf);

	lua_pushlstring(L, buf, sizeof(buf));
	return 1;
}


static int lua_sha384(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

    BYTE buf[384/8];
	struct sha384_state ctx;

	sha384_init(&ctx);
	sha384_process(&ctx, in, in_len);
	sha384_done(&ctx, buf);

	lua_pushlstring(L, buf, sizeof(buf));
	return 1;
}


static int lua_sha512(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	size_t in_len = 0;
	const char *in = lua_tolstring(L, 1, &in_len);

    BYTE buf[512/8];
	struct sha512_state ctx;

	sha512_init(&ctx);
	sha512_process(&ctx, in, in_len);
	sha512_done(&ctx, buf);

	lua_pushlstring(L, buf, sizeof(buf));
	return 1;
}


static const struct luaL_Reg funclist[] = {
	/* encode and decode */
	{ "base64_encode", lua_base64_encode },
	{ "base64_decode", lua_base64_decode },
	{ "hex_encode", lua_hex_encode },
	{ "hex_decode", lua_hex_decode },

	/* block ciphers */
	{ "aes_prepare_key", lua_aes_prepare_key },
	{ "aes_encrypt", lua_aes_encrypt },
	{ "aes_decrypt", lua_aes_decrypt },
	{ "blowfish_prepare_key", lua_blowfish_prepare_key },
	{ "blowfish_encrypt", lua_blowfish_encrypt },
	{ "blowfish_decrypt", lua_blowfish_decrypt },
	{ "des_prepare_key", lua_des_prepare_key },
	{ "des_encrypt", lua_des_encrypt },
	{ "des_decrypt", lua_des_decrypt },
	{ "set_cipher_mode", lua_set_cipher_mode },
	{ "get_cipher_info", lua_get_cipher_info },

	/* stream ciphers */
	{ "rc4_prepare_key", lua_rc4_prepare_key },
	{ "rc4", lua_rc4 },

	/* checksums and hash functions */
	{ "crc16", lua_crc16 },
	{ "crc32", lua_crc32 },
	{ "md2", lua_md2 },
	{ "md5", lua_md5 },
	{ "sha1", lua_sha1 },
	{ "sha224", lua_sha224 },
	{ "sha256", lua_sha256 },
	{ "sha384", lua_sha384 },
	{ "sha512", lua_sha512 },

	/* other */
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
