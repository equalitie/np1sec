/*
 * purple
 *
 * File: win32dep.c
 * Date: June, 2002
 * Description: Windows dependant code for Purple
 *
 * Copyright (C) 2002-2003, Herman Bloggs <hermanator12002@yahoo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 */
#define _WIN32_IE 0x501
#include "internal.h"
#include <winuser.h>

#include "debug.h"
#include "notify.h"

/*
 * LOCALS
 */
static char *app_data_dir = NULL, *install_dir = NULL,
	*lib_dir = NULL, *locale_dir = NULL;

static HINSTANCE libpurpledll_hInstance = NULL;

/*
 *  PUBLIC CODE
 */

/* Escape windows dir separators.  This is needed when paths are saved,
   and on being read back have their '\' chars used as an escape char.
   Returns an allocated string which needs to be freed.
*/
char *wpurple_escape_dirsep(const char *filename) {
	int sepcount = 0;
	const char *tmp = filename;
	char *ret;
	int cnt = 0;

	g_return_val_if_fail(filename != NULL, NULL);

	while(*tmp) {
		if(*tmp == '\\')
			sepcount++;
		tmp++;
	}
	ret = g_malloc0(strlen(filename) + sepcount + 1);
	while(*filename) {
		ret[cnt] = *filename;
		if(*filename == '\\')
			ret[++cnt] = '\\';
		filename++;
		cnt++;
	}
	ret[cnt] = '\0';
	return ret;
}

/* Determine whether the specified dll contains the specified procedure.
   If so, load it (if not already loaded). */
FARPROC wpurple_find_and_loadproc(const char *dllname, const char *procedure) {
	HMODULE hmod;
	BOOL did_load = FALSE;
	FARPROC proc = 0;

	wchar_t *wc_dllname = g_utf8_to_utf16(dllname, -1, NULL, NULL, NULL);

	if(!(hmod = GetModuleHandleW(wc_dllname))) {
		purple_debug_warning("wpurple", "%s not already loaded; loading it...\n", dllname);
		if(!(hmod = LoadLibraryW(wc_dllname))) {
			purple_debug_error("wpurple", "Could not load: %s (%s)\n", dllname,
				g_win32_error_message(GetLastError()));
			g_free(wc_dllname);
			return NULL;
		}
		else
			did_load = TRUE;
	}

	g_free(wc_dllname);
	wc_dllname = NULL;

	if((proc = GetProcAddress(hmod, procedure))) {
		purple_debug_info("wpurple", "This version of %s contains %s\n",
			dllname, procedure);
		return proc;
	}
	else {
		purple_debug_warning("wpurple", "Function %s not found in dll %s\n",
			procedure, dllname);
		if(did_load) {
			/* unload dll */
			FreeLibrary(hmod);
		}
		return NULL;
	}
}

/* Determine Purple Paths during Runtime */

/* Get paths to special Windows folders. */
gchar *wpurple_get_special_folder(int folder_type) {
	gchar *retval = NULL;
	wchar_t utf_16_dir[MAX_PATH + 1];

	if (SUCCEEDED(SHGetFolderPathW(NULL, folder_type, NULL,
					SHGFP_TYPE_CURRENT, utf_16_dir))) {
		retval = g_utf16_to_utf8(utf_16_dir, -1, NULL, NULL, NULL);
	}

	return retval;
}

const char *wpurple_install_dir(void) {
	static gboolean initialized = FALSE;

	if (!initialized) {
		char *tmp = NULL;
		wchar_t winstall_dir[MAXPATHLEN];
		if (GetModuleFileNameW(libpurpledll_hInstance, winstall_dir,
				MAXPATHLEN) > 0) {
			tmp = g_utf16_to_utf8(winstall_dir, -1,
				NULL, NULL, NULL);
		}

		if (tmp == NULL) {
			tmp = g_win32_error_message(GetLastError());
			purple_debug_error("wpurple",
				"GetModuleFileName error: %s\n", tmp);
			g_free(tmp);
			return NULL;
		} else {
			install_dir = g_path_get_dirname(tmp);
			g_free(tmp);
			initialized = TRUE;
		}
	}

	return install_dir;
}

const char *wpurple_lib_dir(void) {
	static gboolean initialized = FALSE;

	if (!initialized) {
		const char *inst_dir = wpurple_install_dir();
		if (inst_dir != NULL) {
			lib_dir = g_strdup_printf("%s" G_DIR_SEPARATOR_S "plugins", inst_dir);
			initialized = TRUE;
		} else {
			return NULL;
		}
	}

	return lib_dir;
}

const char *wpurple_locale_dir(void) {
	static gboolean initialized = FALSE;

	if (!initialized) {
		const char *inst_dir = wpurple_install_dir();
		if (inst_dir != NULL) {
			locale_dir = g_strdup_printf("%s" G_DIR_SEPARATOR_S "locale", inst_dir);
			initialized = TRUE;
		} else {
			return NULL;
		}
	}

	return locale_dir;
}

const char *wpurple_data_dir(void) {

	if (!app_data_dir) {
		/* Set app data dir, used by purple_home_dir */
		const char *newenv = g_getenv("PURPLEHOME");
		if (newenv)
			app_data_dir = g_strdup(newenv);
		else {
			app_data_dir = wpurple_get_special_folder(CSIDL_APPDATA);
			if (!app_data_dir)
				app_data_dir = g_strdup("C:");
		}
		purple_debug_info("wpurple", "Purple settings dir: %s\n",
			app_data_dir);
	}

	return app_data_dir;
}

/* Miscellaneous */

gboolean wpurple_write_reg_string(HKEY rootkey, const char *subkey, const char *valname,
		const char *value) {
	HKEY reg_key;
	gboolean success = FALSE;

	wchar_t *wc_subkey = g_utf8_to_utf16(subkey, -1, NULL,
		NULL, NULL);

	if(RegOpenKeyExW(rootkey, wc_subkey, 0,
			KEY_SET_VALUE, &reg_key) == ERROR_SUCCESS) {
		wchar_t *wc_valname = NULL;

		if (valname)
			wc_valname = g_utf8_to_utf16(valname, -1,
				NULL, NULL, NULL);

		if(value) {
			wchar_t *wc_value = g_utf8_to_utf16(value, -1,
				NULL, NULL, NULL);
			int len = (wcslen(wc_value) * sizeof(wchar_t)) + 1;
			if(RegSetValueExW(reg_key, wc_valname, 0, REG_SZ,
					(LPBYTE)wc_value, len
					) == ERROR_SUCCESS)
				success = TRUE;
			g_free(wc_value);
		} else
			if(RegDeleteValueW(reg_key, wc_valname) ==  ERROR_SUCCESS)
				success = TRUE;

		g_free(wc_valname);
	}
	g_free(wc_subkey);

	if(reg_key != NULL)
		RegCloseKey(reg_key);

	return success;
}

static HKEY _reg_open_key(HKEY rootkey, const char *subkey, REGSAM access) {
	HKEY reg_key = NULL;
	LONG rv;

	wchar_t *wc_subkey = g_utf8_to_utf16(subkey, -1, NULL,
		NULL, NULL);
	rv = RegOpenKeyExW(rootkey, wc_subkey, 0, access, &reg_key);

	g_free(wc_subkey);

	if (rv != ERROR_SUCCESS) {
		char *errmsg = g_win32_error_message(rv);
		purple_debug_error("wpurple", "Could not open reg key '%s' subkey '%s'.\nMessage: (%ld) %s\n",
					((rootkey == HKEY_LOCAL_MACHINE) ? "HKLM" :
					 (rootkey == HKEY_CURRENT_USER) ? "HKCU" :
					  (rootkey == HKEY_CLASSES_ROOT) ? "HKCR" : "???"),
					subkey, rv, errmsg);
		g_free(errmsg);
	}

	return reg_key;
}

static gboolean _reg_read(HKEY reg_key, const char *valname, LPDWORD type, LPBYTE data, LPDWORD data_len) {
	LONG rv;

	wchar_t *wc_valname = NULL;
	if (valname)
		wc_valname = g_utf8_to_utf16(valname, -1, NULL, NULL, NULL);
	rv = RegQueryValueExW(reg_key, wc_valname, 0, type, data, data_len);
	g_free(wc_valname);

	if (rv != ERROR_SUCCESS) {
		char *errmsg = g_win32_error_message(rv);
		purple_debug_error("wpurple", "Could not read from reg key value '%s'.\nMessage: (%ld) %s\n",
					valname, rv, errmsg);
		g_free(errmsg);
	}

	return (rv == ERROR_SUCCESS);
}

gboolean wpurple_read_reg_dword(HKEY rootkey, const char *subkey, const char *valname, LPDWORD result) {

	DWORD type;
	DWORD nbytes;
	HKEY reg_key = _reg_open_key(rootkey, subkey, KEY_QUERY_VALUE);
	gboolean success = FALSE;

	if(reg_key) {
		if(_reg_read(reg_key, valname, &type, (LPBYTE)result, &nbytes))
			success = TRUE;
		RegCloseKey(reg_key);
	}

	return success;
}

char *wpurple_read_reg_string(HKEY rootkey, const char *subkey, const char *valname) {

	DWORD type;
	DWORD nbytes;
	HKEY reg_key = _reg_open_key(rootkey, subkey, KEY_QUERY_VALUE);
	char *result = NULL;

	if(reg_key) {
		if(_reg_read(reg_key, valname, &type, NULL, &nbytes) && type == REG_SZ) {
			LPBYTE data = (LPBYTE) g_new(wchar_t, ((nbytes + 1) / sizeof(wchar_t)) + 1);

			if(_reg_read(reg_key, valname, &type, data, &nbytes)) {
				wchar_t *wc_temp = (wchar_t*) data;
				wc_temp[nbytes / sizeof(wchar_t)] = '\0';
				result = g_utf16_to_utf8(wc_temp, -1,
					NULL, NULL, NULL);
			}
			g_free(data);
		}
		RegCloseKey(reg_key);
	}

	return result;
}

void wpurple_init(void) {
	WORD wVersionRequested;
	WSADATA wsaData;

	if (!g_thread_supported())
		g_thread_init(NULL);

	purple_debug_info("wpurple", "wpurple_init start\n");
	purple_debug_info("wpurple", "libpurple version: " DISPLAY_VERSION "\n");

	purple_debug_info("wpurple", "Glib:%u.%u.%u\n",
		glib_major_version, glib_minor_version, glib_micro_version);

	/* Winsock init */
	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);

	/* Confirm that the winsock DLL supports 2.2 */
	/* Note that if the DLL supports versions greater than
	   2.2 in addition to 2.2, it will still return 2.2 in
	   wVersion since that is the version we requested. */
	if(LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		purple_debug_error("wpurple", "Could not find a usable WinSock DLL.  Oh well.\n");
		WSACleanup();
	}

	purple_debug_info("wpurple", "wpurple_init end\n");
}

/* Windows Cleanup */

void wpurple_cleanup(void) {
	purple_debug_info("wpurple", "wpurple_cleanup\n");

	/* winsock cleanup */
	WSACleanup();

	g_free(app_data_dir);
	g_free(install_dir);
	g_free(lib_dir);
	g_free(locale_dir);

	app_data_dir = NULL;
	install_dir = NULL;
	lib_dir = NULL;
	locale_dir = NULL;

	libpurpledll_hInstance = NULL;
}

long
wpurple_get_tz_offset() {
	TIME_ZONE_INFORMATION tzi;
	DWORD ret;
	long off = -1;

	if ((ret = GetTimeZoneInformation(&tzi)) != TIME_ZONE_ID_INVALID)
	{
		off = -(tzi.Bias * 60);
		if (ret == TIME_ZONE_ID_DAYLIGHT)
			off -= tzi.DaylightBias * 60;
	}

	return off;
}

/* DLL initializer */
/* suppress gcc "no previous prototype" warning */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	libpurpledll_hInstance = hinstDLL;
	return TRUE;
}
