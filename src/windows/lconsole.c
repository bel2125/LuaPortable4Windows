#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "lua_all.h"
#define stricmp _stricmp


static int lua_SetTextColor(lua_State *L)
{
	return 0;
}


static int lua_SetConsoleTitle(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	const char *text = lua_tostring(L, 1);

	WCHAR title[256];
	MultiByteToWideChar(CP_UTF8, 0, text, -1, title, 255);
	SetConsoleTitleW(title);

	return 0;
}


static int lua_SetConsoleCursorPosition(lua_State *L)
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE); 
	COORD c = { 5, 16 };

	SetConsoleCursorPosition(hOut, c);
}


static const struct luaL_Reg funclist[] = {
	{ "SetTextColor", lua_SetTextColor },
	{ "SetConsoleTitle", lua_SetConsoleTitle },
	{ "SetConsoleCursorPosition", lua_SetConsoleCursorPosition },

	{ NULL, NULL },
};


int luaopen_console(lua_State *L)
{
	luaL_newlib(L, funclist);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "console");
	return 1;
}
