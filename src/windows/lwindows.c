#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "lua_all.h"
#define stricmp _stricmp


static int lua_MessageBox(lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	const char *text = lua_tostring(L, 1);

	if (lua_type(L, 2) != LUA_TSTRING) {
		return luaL_error(L, "%s parameter error", __func__);
	}
	const char *caption = lua_tostring(L, 2);

	double type = 0;
	if (lua_type(L, 3) == LUA_TNUMBER) {
		type = lua_tonumber(L, 3);
	} else if ((lua_type(L,3) != LUA_TNONE) && (lua_type(L, 3) != LUA_TNIL)) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	int ret = MessageBoxA(NULL, text, caption, (UINT)type);

	lua_pushnumber(L, ret);
	return 1;
}


static int lua_GetOpenFileName(lua_State *L)
{
	OPENFILENAMEA ofn;
	char fn[MAX_PATH];
	char filter[256];

	memset(&ofn, 0, sizeof(ofn));
	memset(&fn, 0, sizeof(fn));
	memset(&filter, 0, sizeof(filter));

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFile = fn;
	ofn.nMaxFile = sizeof(fn);
	ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;

	if (lua_type(L, 1) == LUA_TSTRING) {
		size_t len = 0;
		const char *t = lua_tolstring(L, 1, &len);
		if (len >= sizeof(fn)) {
			return luaL_error(L, "%s parameter error", __func__);
		}
		memcpy(fn, t, len);
	}

	if (lua_type(L, 2) == LUA_TSTRING) {
		size_t len = 0;
		const char *t = lua_tolstring(L, 2, &len);
		if (len+2 >= sizeof(filter)) {
			return luaL_error(L, "%s parameter error", __func__);
		}
		memcpy(filter, t, len);
		ofn.lpstrFilter = filter;
	}

	int ok = GetOpenFileNameA(&ofn);
	if (ok) {
		lua_pushboolean(L, 1);
		lua_pushstring(L, fn);
		return 2;
	}
	lua_pushboolean(L, 0);
	lua_pushnil(L);
	return 2;
}


static int lua_GetSaveFileName(lua_State *L)
{
	OPENFILENAMEA ofn;
	char fn[MAX_PATH];
	char filter[256];

	memset(&ofn, 0, sizeof(ofn));
	memset(&fn, 0, sizeof(fn));
	memset(&filter, 0, sizeof(filter));

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFile = fn;
	ofn.nMaxFile = sizeof(fn);
	ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

	if (lua_type(L, 1) == LUA_TSTRING) {
		size_t len = 0;
		const char *t = lua_tolstring(L, 1, &len);
		if (len >= sizeof(fn)) {
			return luaL_error(L, "%s parameter error", __func__);
		}
		memcpy(fn, t, len);
	}

	if (lua_type(L, 2) == LUA_TSTRING) {
		size_t len = 0;
		const char *t = lua_tolstring(L, 2, &len);
		if (len + 2 >= sizeof(filter)) {
			return luaL_error(L, "%s parameter error", __func__);
		}
		memcpy(filter, t, len);
		ofn.lpstrFilter = filter;
	}

	int ok = GetSaveFileNameA(&ofn);
	if (ok) {
		lua_pushboolean(L, 1);
		lua_pushstring(L, fn);
		return 2;
	}
	lua_pushboolean(L, 0);
	lua_pushnil(L);
	return 2;
}


/* LPARAM pointer passed to WM_INITDIALOG */
struct dlg_proc_param {
	HWND hWnd;
	lua_State *L;
}; 

static INT_PTR CALLBACK
DialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	struct dlg_proc_param * pdlg_proc_param = 0;

	switch (msg) {

	case WM_CLOSE:
		DestroyWindow(hDlg);
		break;

	case WM_COMMAND:
		//switch (LOWORD(wParam)) {
		//}

		break;

	case WM_INITDIALOG:
		pdlg_proc_param = (struct dlg_proc_param *)lParam;
		pdlg_proc_param->hWnd = hDlg;
		break;

	default:
		break;
	}

	return FALSE;
}


LPWORD lpwAlign(LPWORD lpIn)
{
	ULONG align = 4;
	return (LPWORD)(((((ULONG)lpIn) + 1) / align) * align);
}


static int lua_InputBox(lua_State *L)
{
	struct dlg_proc_param dlg_prm;
	memset(&dlg_prm, 0, sizeof(dlg_prm));

	if (lua_type(L, 1) != LUA_TTABLE) {
		return luaL_error(L, "%s parameter error", __func__);
	}

	HINSTANCE hinst = NULL;
	HWND hwndOwner = NULL;

	HGLOBAL hgbl;
	LPDLGTEMPLATE lpdt;
	LPDLGITEMTEMPLATE lpdit;
	LPWORD lpw;
	LPWSTR lpwsz;
	LRESULT ret;
	int nchar;

	hgbl = GlobalAlloc(GMEM_ZEROINIT, 1024*16);
	if (!hgbl) {
		return -1;
	}
	lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);

	//-----------------------
	// Define a dialog box, including title.
	//-----------------------
	lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU | DS_MODALFRAME | WS_CAPTION;

	/* get title */
	const char *title = "";
	int ltype = lua_getfield(L, 1, "title");
	if (ltype == LUA_TSTRING) {
		title = lua_tostring(L, -1);
	}
	lua_pop(L, 1);

	/* get coordinates */
	lpdt->x = 10;  lpdt->y = 10;
	lpdt->cx = 100; lpdt->cy = -1;
	ltype = lua_getfield(L, 1, "x");
	if (ltype == LUA_TNUMBER) {
		lpdt->x = lua_tointeger(L, -1);
	}
	ltype = lua_getfield(L, 1, "y");
	if (ltype == LUA_TNUMBER) {
		lpdt->y = lua_tointeger(L, -1);
	}
	ltype = lua_getfield(L, 1, "cx");
	if (ltype == LUA_TNUMBER) {
		lpdt->cx = lua_tointeger(L, -1);
	}
	ltype = lua_getfield(L, 1, "cy");
	if (ltype == LUA_TNUMBER) {
		lpdt->cy = lua_tointeger(L, -1);
	}
	lua_pop(L, 4);

	lpw = (LPWORD)(lpdt + 1);
	*lpw++ = 0;             // No menu
	*lpw++ = 0;             // Predefined dialog box class (by default)

	lpwsz = (LPWSTR)lpw;
	nchar = 1 + MultiByteToWideChar(CP_UTF8, 0, title, -1, lpwsz, 50);
	lpw += nchar;
	lpdt->cdit = 0; // Number of items in dialog. Add them in a loop.

	//-----------------------
	// Dialog items
	//-----------------------
	ltype = lua_getfield(L, 1, "items");
	if (ltype == LUA_TTABLE) {
		lua_pushnil(L);
		while (lua_next(L, -2) != 0) {
			int key_type = lua_type(L, -2);
			int value_type = lua_type(L, -1);

			if (((key_type == LUA_TSTRING) || (key_type == LUA_TNUMBER)) && (value_type == LUA_TTABLE)) {
				// Add one dialog item
				printf("PNU %p\n", lpw);
				lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
				printf("PNA %p\n", lpw);
				lpdit = (LPDLGITEMTEMPLATE)lpw;

				lpdit->x = 10; 
				lpdit->y = 10+20*lpdt->cdit;
				lpdit->cx = 80;
				lpdit->cy = 15;
				const char *itemtype = "";
				const char *itemtext = "";

				ltype = lua_getfield(L, -1, "type");
				if (ltype == LUA_TSTRING) {
					itemtype = lua_tostring(L, -1);
				}
				lua_pop(L, 1);
				ltype = lua_getfield(L, -1, "text");
				if (ltype == LUA_TSTRING) {
					itemtext = lua_tostring(L, -1);
				}
				lua_pop(L, 1);
				ltype = lua_getfield(L, -1, "x");
				if (ltype == LUA_TNUMBER) {
					lpdit->x = lua_tointeger(L, -1);
				}
				lua_pop(L, 1);
				ltype = lua_getfield(L, -1, "y");
				if (ltype == LUA_TNUMBER) {
					lpdit->y = lua_tointeger(L, -1);
				}
				lua_pop(L, 1);
				ltype = lua_getfield(L, -1, "cx");
				if (ltype == LUA_TNUMBER) {
					lpdit->cx = lua_tointeger(L, -1);
				}
				lua_pop(L, 1);
				ltype = lua_getfield(L, -1, "cy");
				if (ltype == LUA_TNUMBER) {
					lpdit->cy = lua_tointeger(L, -1);
				}
				lua_pop(L, 1);

				/* type/class */
				lpdt->cdit++;
				lpdit->id = (lpdt->cdit);       // Item identifier
				lpdit->style = WS_CHILD | WS_VISIBLE;
				lpdit->dwExtendedStyle = 0;
				if (lpdit->id == 1) lpdit->style |= BS_DEFPUSHBUTTON;

				// see https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgitemtemplate
				WORD dlg_class = 0x0082;
				if (!stricmp(itemtype, "button")) {
					dlg_class = 0x0080;
				}
				if (!stricmp(itemtype, "check")) {
					dlg_class = 0x0080;
					lpdit->style |= BS_AUTOCHECKBOX;
				}
				if (!stricmp(itemtype, "radio")) {
					dlg_class = 0x0080;
					lpdit->style |= BS_AUTORADIOBUTTON;
				}
				if (!stricmp(itemtype, "edit")) {
					dlg_class = 0x0081;
					lpdit->style |= WS_BORDER | ES_AUTOHSCROLL;
				}
				if (!stricmp(itemtype, "number")) {
					dlg_class = 0x0081;
					lpdit->style |= WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER;
				}
				if (!stricmp(itemtype, "static")) {
					dlg_class = 0x0082;
				}
				if (!stricmp(itemtype, "list")) {
					dlg_class = 0x0083;
				}
				if (!stricmp(itemtype, "scroll")) {
					dlg_class = 0x0084;
				}
				if (!stricmp(itemtype, "combo")) {
					dlg_class = 0x0085;
				}

				lpw = (LPWORD)(lpdit + 1);
				*lpw++ = 0xFFFF;
				*lpw++ = dlg_class;

				lpwsz = (LPWSTR)lpw;
				nchar = 1 + MultiByteToWideChar(CP_UTF8, 0, itemtext, -1, lpwsz, 100);
				lpw += nchar;
				*lpw++ = 0;             // No creation data
			}	
			lua_pop(L, 1);
		}
	}
	//-----------------------  
	if (lpdt->cy < 0) {
		lpdt->cy = 20 + 20 * lpdt->cdit;
	}

#if 0
	//-----------------------
	// Define an OK button.
	//-----------------------
	lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
	lpdit = (LPDLGITEMTEMPLATE)lpw;
	lpdit->x = 10; lpdit->y = 70;
	lpdit->cx = 80; lpdit->cy = 20;
	lpdit->id = IDOK;       // OK button identifier
	lpdit->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON;

	lpw = (LPWORD)(lpdit + 1);
	*lpw++ = 0xFFFF;
	*lpw++ = 0x0080;        // Button class

	lpwsz = (LPWSTR)lpw;
	nchar = 1 + MultiByteToWideChar(CP_ACP, 0, "OK", -1, lpwsz, 50);
	lpw += nchar;
	*lpw++ = 0;             // No creation data

	//-----------------------
	// Define a Help button.
	//-----------------------
	lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
	lpdit = (LPDLGITEMTEMPLATE)lpw;
	lpdit->x = 55; lpdit->y = 10;
	lpdit->cx = 40; lpdit->cy = 20;
	lpdit->id = ID_HELP;    // Help button identifier
	lpdit->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;

	lpw = (LPWORD)(lpdit + 1);
	*lpw++ = 0xFFFF;
	*lpw++ = 0x0080;        // Button class atom: https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgitemtemplate

	lpwsz = (LPWSTR)lpw;
	nchar = 1 + MultiByteToWideChar(CP_ACP, 0, "Help", -1, lpwsz, 50);
	lpw += nchar;
	*lpw++ = 0;             // No creation data

	//-----------------------
	// Define a static text control.
	//-----------------------
	lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
	lpdit = (LPDLGITEMTEMPLATE)lpw;
	lpdit->x = 10; lpdit->y = 10;
	lpdit->cx = 40; lpdit->cy = 20;
	lpdit->id = ID_TEXT;    // Text identifier
	lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT;

	lpw = (LPWORD)(lpdit + 1);
	*lpw++ = 0xFFFF;
	*lpw++ = 0x0082;        // Static class

	const char*message = "bla";
	for (lpwsz = (LPWSTR)lpw; *lpwsz++ = (WCHAR)*message++;);
	lpw = (LPWORD)lpwsz;
	*lpw++ = 0;             // No creation data
#endif

	GlobalUnlock(hgbl);
	ret = DialogBoxIndirectParamA(hinst,
		(LPDLGTEMPLATE)hgbl,
		hwndOwner,
		(DLGPROC)DialogProc,
		&dlg_prm);
	GlobalFree(hgbl);

	return 0;
}



static const struct luaL_Reg funclist[] = {
	{ "MessageBox", lua_MessageBox },
	{ "GetOpenFileName", lua_GetOpenFileName },
	{ "GetSaveFileName", lua_GetSaveFileName },
	{ "InputBox", lua_InputBox },

	{ NULL, NULL },
};


int luaopen_windows(lua_State *L)
{
	luaL_newlib(L, funclist);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "windows");
	return 1;
}
