#ifndef LUA_ALL_H
#define LUA_ALL_H

#include "lauxlib.h"
#include "lua.h"

void LUAPORTABLE4WINDOWS_OPENLIBS(lua_State *L);
void LUAPORTABLE4WINDOWS_PRINTVERSION();
lua_CFunction LUAPORTABLE4WINDOWS_MAIN(lua_CFunction defaultMain);

#endif /* #ifndef CIVETWEB_LUA_H */
