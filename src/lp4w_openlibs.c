#include "lua_all.h"
#include "lualib.h"
#include "lfs/lfs.h"
extern int luaopen_lsqlite3(lua_State *L);
extern int luaopen_crypto(lua_State *L);
extern int luaopen_windows(lua_State *L);


static void po_elm(lua_State *L, int arg, int recurse) 
{
	int t = lua_type(L, arg);
	switch (t) {
	case LUA_TNIL:
	{
		printf("nil\n");
		break;
	}
	case LUA_TBOOLEAN:
	{
		int b = lua_toboolean(L, arg);
		printf("boolean: %s\n", b ? "true" : "false");
		break;
	}
	case LUA_TLIGHTUSERDATA:
	{
		void *p = lua_touserdata(L, arg);
		printf("light user data: %p\n", p);
		break;
	}
	case LUA_TNUMBER:
	{
		double n = lua_tonumber(L, arg);
		printf("number: %lG\n", n);
		break;
	}
	case LUA_TSTRING:
	{
		size_t len = 0;
		const char *s = lua_tolstring(L, arg, &len);
		if (len > 44) {
			printf("string(%lu): %.40s ...\n", (unsigned long)len, s);
		}
		else {
			printf("string(%lu): %s\n", (unsigned long)len, s);
		}
		break;
	}
	case LUA_TTABLE:
	if (recurse > 0) {
		printf("table:\n");
		lua_pushnil(L);
		while (lua_next(L, -2) != 0) {
			printf("  key: ");
			po_elm(L, -2, recurse-1);
			printf("  val: ");
			po_elm(L, -1, recurse - 1);
			lua_pop(L, 1);
			printf("\n");
		}
	}
	else {
		printf("table\n");
	}
	break;
	case LUA_TFUNCTION:
	{
		void *p = lua_tocfunction(L, arg);
		printf("function: %p\n", p);
		break;
	}
	case LUA_TUSERDATA:
	{
		void *p = lua_touserdata(L, arg);
		printf("user data: %p\n", p);
		break;
	}
	case LUA_TTHREAD:
	{
		lua_State *T = lua_tothread(L, arg);
		printf("thread: %p\n", (void*)T);
		break;
	}
	case LUA_TNONE:
	{
		break;
	}
	default:
		printf("unknown type %i\n", t);
		break;
	}
}


static int PO(lua_State *L)
{
	int args = lua_gettop(L);
	if (args != 1) {
		return luaL_error(L, "Invalid call to po");
	}
	po_elm(L, 1, 1);

	return 0;
}


void LUAPORTABLE4WINDOWS_OPENLIBS(lua_State *L) 
{
	(void)luaopen_lfs(L);
	(void)luaopen_lsqlite3(L);
	(void)luaopen_crypto(L);
	(void)luaopen_windows(L);

	lua_pushcfunction(L, PO);
	lua_setglobal(L, "po");
}
