#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "lua_all.h"


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


#define ID_HELP   150
#define ID_TEXT   200

LPWORD lpwAlign(LPWORD lpIn)
{
	ULONG ul;

	ul = (ULONG)lpIn;
	ul++;
	ul >>= 1;
	ul <<= 1;
	return (LPWORD)ul;
}


/* https://docs.microsoft.com/en-us/windows/win32/dlgbox/using-dialog-boxes */
LRESULT DisplayMyMessage(LPSTR lpszMessage, LPARAM param)
{
	HINSTANCE hinst = NULL;
	HWND hwndOwner = NULL;

	HGLOBAL hgbl;
	LPDLGTEMPLATE lpdt;
	LPDLGITEMTEMPLATE lpdit;
	LPWORD lpw;
	LPWSTR lpwsz;
	LRESULT ret;
	int nchar;

	hgbl = GlobalAlloc(GMEM_ZEROINIT, 1024);
	if (!hgbl)
		return -1;

	lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);

	// Define a dialog box.

	lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU | DS_MODALFRAME | WS_CAPTION;
	lpdt->cdit = 3;         // Number of controls
	lpdt->x = 10;  lpdt->y = 10;
	lpdt->cx = 100; lpdt->cy = 100;

	lpw = (LPWORD)(lpdt + 1);
	*lpw++ = 0;             // No menu
	*lpw++ = 0;             // Predefined dialog box class (by default)

	lpwsz = (LPWSTR)lpw;
	nchar = 1 + MultiByteToWideChar(CP_ACP, 0, "My Dialog", -1, lpwsz, 50);
	lpw += nchar;

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
	*lpw++ = 0x0080;        // Button class atom

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

	for (lpwsz = (LPWSTR)lpw; *lpwsz++ = (WCHAR)*lpszMessage++;);
	lpw = (LPWORD)lpwsz;
	*lpw++ = 0;             // No creation data

	GlobalUnlock(hgbl);
	ret = DialogBoxIndirectParamA(hinst,
		(LPDLGTEMPLATE)hgbl,
		hwndOwner,
		(DLGPROC)DialogProc,
		param);
	GlobalFree(hgbl);
	return ret;
}


static int lua_InputBox(lua_State *L)
{
	struct dlg_proc_param dlg_prm;

	memset(&dlg_prm, 0, sizeof(dlg_prm));

	LPARAM res = DisplayMyMessage("bla", (LPARAM)&dlg_prm);
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
