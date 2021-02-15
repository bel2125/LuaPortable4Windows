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
	int ret;
}; 


static INT_PTR CALLBACK
DialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {

	case WM_CLOSE:
	{
		struct dlg_proc_param * pdlg_proc_param = (struct dlg_proc_param *)GetWindowLongPtr(hDlg, GWLP_USERDATA);
		if ((pdlg_proc_param->hWnd == hDlg) && (pdlg_proc_param->L != NULL)) {
			// condition should always be true
			lua_pushinteger(pdlg_proc_param->L, 0);
			pdlg_proc_param->ret = 1;
		}
		DestroyWindow(hDlg);
	}
	break;

	case WM_COMMAND:
	{
		WORD wmId = LOWORD(wParam);
		WORD wmEvent = HIWORD(wParam);
		HWND dlg = GetDlgItem(hDlg, wmId);

		if (wmEvent == 0) {
			if (wmId >= 0x1000) {
				int result = wmId - 0x1000;
				struct dlg_proc_param * pdlg_proc_param = (struct dlg_proc_param *)GetWindowLongPtr(hDlg, GWLP_USERDATA);
				if ((pdlg_proc_param->hWnd == hDlg) && (pdlg_proc_param->L != NULL)) {
					// condition should always be true
					lua_pushinteger(pdlg_proc_param->L, result);
					lua_newtable(pdlg_proc_param->L);
					pdlg_proc_param->ret = 2;
					int tabIndex = 0;

					for (int i = 1; i < 0x1000; i++) {
						HWND hItem = GetDlgItem(hDlg, i);
						if (!hItem) break;
						char className[32] = { 0 };
						GetClassName(hItem, className, sizeof(className));

						if (!stricmp(className, "Button")) {

							UINT r = IsDlgButtonChecked(hDlg, i);
							if (r == BST_CHECKED) {
								lua_pushboolean(pdlg_proc_param->L, 1);
							}
							else if (r == BST_UNCHECKED) {
								lua_pushboolean(pdlg_proc_param->L, 0);
							}
							else {
								lua_pushnil(pdlg_proc_param->L);
							}
							lua_rawseti(pdlg_proc_param->L, -2, ++tabIndex);

						} else if (!stricmp(className, "Edit")) {

							DWORD dwStyle = (DWORD)GetWindowLong(hItem, GWL_STYLE);
							int len = GetWindowTextLengthW(hItem)+1;
							LPWSTR utf16 = (LPWSTR)malloc(len * sizeof(WCHAR));
							if (!utf16) continue;

							GetWindowTextW(hItem, utf16, len);

							char *utf8 = (char*)malloc(len * 3);
							if (!utf8) {
								free(utf16);
								continue;
							}

							WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, len * 3, NULL, NULL);

							if ((dwStyle & ES_NUMBER) == ES_NUMBER) {
								long long nr = strtoll(utf8, NULL, 10);
								lua_pushnumber(pdlg_proc_param->L, nr);
							} else {
								lua_pushstring(pdlg_proc_param->L, utf8);
							}
							lua_rawseti(pdlg_proc_param->L, -2, ++tabIndex);

							free(utf8);
							free(utf16);
						}
					}
					// all parameters stored to Lua state
				}
				EndDialog(hDlg, result);
			}
		}
	}
	break;

	case WM_INITDIALOG:
	{
		struct dlg_proc_param * pdlg_proc_param = (struct dlg_proc_param *)lParam;
		pdlg_proc_param->hWnd = hDlg;
		pdlg_proc_param->ret = 0;
		SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)pdlg_proc_param);
	}
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


#define MAX(a,b) (((a)>(b))?(a):(b))

static int lua_InputBox(lua_State *L)
{
	struct dlg_proc_param dlg_prm;
	memset(&dlg_prm, 0, sizeof(dlg_prm));
	dlg_prm.L = L;
	SHORT button_count = 0;
	SHORT input_count = 0;

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
	lpdt->cx = 20; lpdt->cy = 20;
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
				lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
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

				/* adjust dialog size */
				lpdt->cx = MAX(lpdt->cx, lpdit->x + lpdit->cx + 10);
				lpdt->cy = MAX(lpdt->cy, lpdit->y + lpdit->cy + 10);

				/* type/class */
				lpdt->cdit++;
				lpdit->id = 0;       // Item identifier
				lpdit->style = WS_CHILD | WS_VISIBLE;
				lpdit->dwExtendedStyle = 0;

				// see https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgitemtemplate
				WORD dlg_class = 0x0082;
				if (!stricmp(itemtype, "button")) {
					button_count++;
					if (button_count == 1) {
						lpdit->style |= BS_DEFPUSHBUTTON;
					} else {
						lpdit->style |= BS_PUSHBUTTON;
					}
					dlg_class = 0x0080;
					lpdit->id = 0x1000 + button_count;
				}
				if (!stricmp(itemtype, "check") || !stricmp(itemtype, "boolean")) {
					input_count++;
					dlg_class = 0x0080;
					lpdit->style |= BS_AUTOCHECKBOX;
					lpdit->id = input_count;
				}
				if (!stricmp(itemtype, "radio")) {
					input_count++;
					dlg_class = 0x0080;
					lpdit->style |= BS_AUTORADIOBUTTON;
					lpdit->id = input_count;
				}
				if (!stricmp(itemtype, "3state")) {
					input_count++;
					dlg_class = 0x0080;
					lpdit->style |= BS_AUTO3STATE;
					lpdit->id = input_count;
				}
				if (!stricmp(itemtype, "edit") || !stricmp(itemtype, "string")) {
					input_count++;
					dlg_class = 0x0081;
					lpdit->style |= WS_BORDER | ES_AUTOHSCROLL;
					lpdit->id = input_count;
				}
				if (!stricmp(itemtype, "text") || !stricmp(itemtype, "multiline")) {
					input_count++;
					dlg_class = 0x0081;
					lpdit->style |= WS_BORDER | ES_AUTOHSCROLL | ES_MULTILINE;
					lpdit->style |= ES_WANTRETURN | WS_VSCROLL | ES_AUTOVSCROLL;
					lpdit->id = input_count;
				}
				if (!stricmp(itemtype, "number")) {
					input_count++;
					dlg_class = 0x0081;
					lpdit->style |= WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER;
					lpdit->id = input_count;
				}
				if (!stricmp(itemtype, "static") || !stricmp(itemtype, "label")) {
					dlg_class = 0x0082;
				}

#if 0 // choose according to LUA data types, not Windows dialog types
				if (!stricmp(itemtype, "list")) {
					dlg_class = 0x0083;
				}
				if (!stricmp(itemtype, "scroll")) {
					dlg_class = 0x0084;
				}
				if (!stricmp(itemtype, "combo")) {
					dlg_class = 0x0085;
				}
#endif

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

	// Set heigth, if not defined  
	if (lpdt->cy < 0) {
		lpdt->cy = 20 + 20 * lpdt->cdit;
	}

	GlobalUnlock(hgbl);
	ret = DialogBoxIndirectParamA(hinst,
		(LPDLGTEMPLATE)hgbl,
		hwndOwner,
		(DLGPROC)DialogProc,
		(LPARAM)&dlg_prm);
	GlobalFree(hgbl);

	return dlg_prm.ret;
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
