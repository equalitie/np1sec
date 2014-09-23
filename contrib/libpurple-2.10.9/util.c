/*
 * @file util.h Utility Functions
 * @ingroup core
 */

/* Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
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
 */
#include "internal.h"

#include "cipher.h"
#include "conversation.h"
#include "core.h"
#include "debug.h"
#include "notify.h"
#include "ntlm.h"
#include "prpl.h"
#include "prefs.h"
#include "util.h"

/* 512KiB Default value for maximum HTTP download size (when the client hasn't
   specified a length) */
#define DEFAULT_MAX_HTTP_DOWNLOAD (512 * 1024)

#define MAX_HTTP_CHUNK_SIZE (10 * 1024 * 1024)

struct _PurpleUtilFetchUrlData
{
	PurpleUtilFetchUrlCallback callback;
	void *user_data;

	struct
	{
		char *user;
		char *passwd;
		char *address;
		int port;
		char *page;

	} website;

	char *url;
	int num_times_redirected;
	gboolean full;
	char *user_agent;
	gboolean http11;
	char *request;
	gsize request_written;
	gboolean include_headers;

	gboolean is_ssl;
	PurpleSslConnection *ssl_connection;
	PurpleProxyConnectData *connect_data;
	int fd;
	guint inpa;

	gboolean got_headers;
	gboolean has_explicit_data_len;
	char *webdata;
	gsize len;
	unsigned long data_len;
	gsize max_len;
	gboolean chunked;
	PurpleAccount *account;
};

static char *custom_user_dir = NULL;
static char *user_dir = NULL;


PurpleMenuAction *
purple_menu_action_new(const char *label, PurpleCallback callback, gpointer data,
                     GList *children)
{
	PurpleMenuAction *act = g_new0(PurpleMenuAction, 1);
	act->label = g_strdup(label);
	act->callback = callback;
	act->data = data;
	act->children = children;
	return act;
}

void
purple_menu_action_free(PurpleMenuAction *act)
{
	g_return_if_fail(act != NULL);

	g_free(act->label);
	g_free(act);
}

void
purple_util_init(void)
{
	/* This does nothing right now.  It exists for symmetry with
	 * purple_util_uninit() and forwards compatibility. */
}

void
purple_util_uninit(void)
{
	/* Free these so we don't have leaks at shutdown. */

	g_free(custom_user_dir);
	custom_user_dir = NULL;

	g_free(user_dir);
	user_dir = NULL;
}

/**************************************************************************
 * Base16 Functions
 **************************************************************************/
gchar *
purple_base16_encode(const guchar *data, gsize len)
{
	int i;
	gchar *ascii = NULL;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(len > 0,   NULL);

	ascii = g_malloc(len * 2 + 1);

	for (i = 0; i < len; i++)
		g_snprintf(&ascii[i * 2], 3, "%02hhx", data[i]);

	return ascii;
}

guchar *
purple_base16_decode(const char *str, gsize *ret_len)
{
	int len, i, accumulator = 0;
	guchar *data;

	g_return_val_if_fail(str != NULL, NULL);

	len = strlen(str);

	g_return_val_if_fail(strlen(str) > 0, 0);
	g_return_val_if_fail(len % 2 == 0,    0);

	data = g_malloc(len / 2);

	for (i = 0; i < len; i++)
	{
		if ((i % 2) == 0)
			accumulator = 0;
		else
			accumulator <<= 4;

		if (isdigit(str[i]))
			accumulator |= str[i] - 48;
		else
		{
			switch(tolower(str[i]))
			{
				case 'a':  accumulator |= 10;  break;
				case 'b':  accumulator |= 11;  break;
				case 'c':  accumulator |= 12;  break;
				case 'd':  accumulator |= 13;  break;
				case 'e':  accumulator |= 14;  break;
				case 'f':  accumulator |= 15;  break;
			}
		}

		if (i % 2)
			data[(i - 1) / 2] = accumulator;
	}

	if (ret_len != NULL)
		*ret_len = len / 2;

	return data;
}

gchar *
purple_base16_encode_chunked(const guchar *data, gsize len)
{
	int i;
	gchar *ascii = NULL;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(len > 0,   NULL);

	/* For each byte of input, we need 2 bytes for the hex representation
	 * and 1 for the colon.
	 * The final colon will be replaced by a terminating NULL
	 */
	ascii = g_malloc(len * 3 + 1);

	for (i = 0; i < len; i++)
		g_snprintf(&ascii[i * 3], 4, "%02hhx:", data[i]);

	/* Replace the final colon with NULL */
	ascii[len * 3 - 1] = 0;

	return ascii;
}


/**************************************************************************
 * Base64 Functions
 **************************************************************************/
static const char alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static const char xdigits[] =
	"0123456789abcdef";

gchar *
purple_base64_encode(const guchar *data, gsize len)
{
	return g_base64_encode(data, len);
}

guchar *
purple_base64_decode(const char *str, gsize *ret_len)
{
	/*
	 * We want to allow ret_len to be NULL for backward compatibility,
	 * but g_base64_decode() requires a valid length variable.  So if
	 * ret_len is NULL then pass in a dummy variable.
	 */
	gsize unused;
	return g_base64_decode(str, ret_len != NULL ? ret_len : &unused);
}

/**************************************************************************
 * Quoted Printable Functions (see RFC 2045).
 **************************************************************************/
guchar *
purple_quotedp_decode(const char *str, gsize *ret_len)
{
	char *n, *new;
	const char *end, *p;

	n = new = g_malloc(strlen (str) + 1);
	end = str + strlen(str);

	for (p = str; p < end; p++, n++) {
		if (*p == '=') {
			if (p[1] == '\r' && p[2] == '\n') { /* 5.1 #5 */
				n -= 1;
				p += 2;
			} else if (p[1] == '\n') { /* fuzzy case for 5.1 #5 */
				n -= 1;
				p += 1;
			} else if (p[1] && p[2]) {
				char *nibble1 = strchr(xdigits, tolower(p[1]));
				char *nibble2 = strchr(xdigits, tolower(p[2]));
				if (nibble1 && nibble2) { /* 5.1 #1 */
					*n = ((nibble1 - xdigits) << 4) | (nibble2 - xdigits);
					p += 2;
				} else { /* This should never happen */
					*n = *p;
				}
			} else { /* This should never happen */
				*n = *p;
			}
		}
		else if (*p == '_')
			*n = ' ';
		else
			*n = *p;
	}

	*n = '\0';

	if (ret_len != NULL)
		*ret_len = n - new;

	/* Resize to take less space */
	/* new = realloc(new, n - new); */

	return (guchar *)new;
}

/**************************************************************************
 * MIME Functions
 **************************************************************************/
char *
purple_mime_decode_field(const char *str)
{
	/*
	 * This is wing's version, partially based on revo/shx's version
	 * See RFC2047 [which apparently obsoletes RFC1342]
	 */
	typedef enum {
		state_start, state_equal1, state_question1,
		state_charset, state_question2,
		state_encoding, state_question3,
		state_encoded_text, state_question4, state_equal2 = state_start
	} encoded_word_state_t;
	encoded_word_state_t state = state_start;
	const char *cur, *mark;
	const char *charset0 = NULL, *encoding0 = NULL, *encoded_text0 = NULL;
	GString *new;

	/* token can be any CHAR (supposedly ISO8859-1/ISO2022), not just ASCII */
	#define token_char_p(c) \
		(c != ' ' && !iscntrl(c) && !strchr("()<>@,;:\"/[]?.=", c))

	/* But encoded-text must be ASCII; alas, isascii() may not exist */
	#define encoded_text_char_p(c) \
		((c & 0x80) == 0 && c != '?' && c != ' ' && isgraph(c))

	g_return_val_if_fail(str != NULL, NULL);

	new = g_string_new(NULL);

	/* Here we will be looking for encoded words and if they seem to be
	 * valid then decode them.
	 * They are of this form: =?charset?encoding?text?=
	 */

	for (cur = str, mark = NULL; *cur; cur += 1) {
		switch (state) {
		case state_equal1:
			if (*cur == '?') {
				state = state_question1;
			} else {
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		case state_question1:
			if (token_char_p(*cur)) {
				charset0 = cur;
				state = state_charset;
			} else { /* This should never happen */
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		case state_charset:
			if (*cur == '?') {
				state = state_question2;
			} else if (!token_char_p(*cur)) { /* This should never happen */
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		case state_question2:
			if (token_char_p(*cur)) {
				encoding0 = cur;
				state = state_encoding;
			} else { /* This should never happen */
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		case state_encoding:
			if (*cur == '?') {
				state = state_question3;
			} else if (!token_char_p(*cur)) { /* This should never happen */
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		case state_question3:
			if (encoded_text_char_p(*cur)) {
				encoded_text0 = cur;
				state = state_encoded_text;
			} else if (*cur == '?') { /* empty string */
				encoded_text0 = cur;
				state = state_question4;
			} else { /* This should never happen */
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		case state_encoded_text:
			if (*cur == '?') {
				state = state_question4;
			} else if (!encoded_text_char_p(*cur)) {
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		case state_question4:
			if (*cur == '=') { /* Got the whole encoded-word */
				char *charset = g_strndup(charset0, encoding0 - charset0 - 1);
				char *encoding = g_strndup(encoding0, encoded_text0 - encoding0 - 1);
				char *encoded_text = g_strndup(encoded_text0, cur - encoded_text0 - 1);
				guchar *decoded = NULL;
				gsize dec_len;
				if (g_ascii_strcasecmp(encoding, "Q") == 0)
					decoded = purple_quotedp_decode(encoded_text, &dec_len);
				else if (g_ascii_strcasecmp(encoding, "B") == 0)
					decoded = purple_base64_decode(encoded_text, &dec_len);
				else
					decoded = NULL;
				if (decoded) {
					gsize len;
					char *converted = g_convert((const gchar *)decoded, dec_len, "utf-8", charset, NULL, &len, NULL);

					if (converted) {
						g_string_append_len(new, converted, len);
						g_free(converted);
					}
					g_free(decoded);
				}
				g_free(charset);
				g_free(encoding);
				g_free(encoded_text);
				state = state_equal2; /* Restart the FSM */
			} else { /* This should never happen */
				g_string_append_len(new, mark, cur - mark + 1);
				state = state_start;
			}
			break;
		default:
			if (*cur == '=') {
				mark = cur;
				state = state_equal1;
			} else {
				/* Some unencoded text. */
				g_string_append_c(new, *cur);
			}
			break;
		} /* switch */
	} /* for */

	if (state != state_start)
		g_string_append_len(new, mark, cur - mark + 1);

	return g_string_free(new, FALSE);;
}


/**************************************************************************
 * Date/Time Functions
 **************************************************************************/

const char *purple_get_tzoff_str(const struct tm *tm, gboolean iso)
{
	static char buf[7];
	long off;
	gint8 min;
	gint8 hrs;
	struct tm new_tm = *tm;

	mktime(&new_tm);

	if (new_tm.tm_isdst < 0)
		g_return_val_if_reached("");

#ifdef _WIN32
	if ((off = wpurple_get_tz_offset()) == -1)
		return "";
#else
# ifdef HAVE_TM_GMTOFF
	off = new_tm.tm_gmtoff;
# else
#  ifdef HAVE_TIMEZONE
	tzset();
	off = -1 * timezone;
#  endif /* HAVE_TIMEZONE */
# endif /* !HAVE_TM_GMTOFF */
#endif /* _WIN32 */

	min = (off / 60) % 60;
	hrs = ((off / 60) - min) / 60;

	if(iso) {
		if (0 == off) {
			strcpy(buf, "Z");
		} else {
			/* please leave the colons...they're optional for iso, but jabber
			 * wants them */
			if(g_snprintf(buf, sizeof(buf), "%+03d:%02d", hrs, ABS(min)) > 6)
				g_return_val_if_reached("");
		}
	} else {
		if (g_snprintf(buf, sizeof(buf), "%+03d%02d", hrs, ABS(min)) > 5)
			g_return_val_if_reached("");
	}

	return buf;
}

/* Windows doesn't HAVE_STRFTIME_Z_FORMAT, but this seems clearer. -- rlaager */
#if !defined(HAVE_STRFTIME_Z_FORMAT) || defined(_WIN32)
static size_t purple_internal_strftime(char *s, size_t max, const char *format, const struct tm *tm)
{
	const char *start;
	const char *c;
	char *fmt = NULL;

	/* Yes, this is checked in purple_utf8_strftime(),
	 * but better safe than sorry. -- rlaager */
	g_return_val_if_fail(format != NULL, 0);

	/* This is fairly efficient, and it only gets
	 * executed on Windows or if the underlying
	 * system doesn't support the %z format string,
	 * for strftime() so I think it's good enough.
	 * -- rlaager */
	for (c = start = format; *c ; c++)
	{
		if (*c != '%')
			continue;

		c++;

#ifndef HAVE_STRFTIME_Z_FORMAT
		if (*c == 'z')
		{
			char *tmp = g_strdup_printf("%s%.*s%s",
			                            fmt ? fmt : "",
			                            c - start - 1,
			                            start,
			                            purple_get_tzoff_str(tm, FALSE));
			g_free(fmt);
			fmt = tmp;
			start = c + 1;
		}
#endif
#ifdef _WIN32
		if (*c == 'Z')
		{
			char *tmp = g_strdup_printf("%s%.*s%s",
			                            fmt ? fmt : "",
			                            c - start - 1,
			                            start,
			                            wpurple_get_timezone_abbreviation(tm));
			g_free(fmt);
			fmt = tmp;
			start = c + 1;
		}
#endif
	}

	if (fmt != NULL)
	{
		size_t ret;

		if (*start)
		{
			char *tmp = g_strconcat(fmt, start, NULL);
			g_free(fmt);
			fmt = tmp;
		}

		ret = strftime(s, max, fmt, tm);
		g_free(fmt);

		return ret;
	}

	return strftime(s, max, format, tm);
}
#else /* HAVE_STRFTIME_Z_FORMAT && !_WIN32 */
#define purple_internal_strftime strftime
#endif

const char *
purple_utf8_strftime(const char *format, const struct tm *tm)
{
	static char buf[128];
	char *locale;
	GError *err = NULL;
	int len;
	char *utf8;

	g_return_val_if_fail(format != NULL, NULL);

	if (tm == NULL)
	{
		time_t now = time(NULL);
		tm = localtime(&now);
	}

	locale = g_locale_from_utf8(format, -1, NULL, NULL, &err);
	if (err != NULL)
	{
		purple_debug_error("util", "Format conversion failed in purple_utf8_strftime(): %s\n", err->message);
		g_error_free(err);
		err = NULL;
		locale = g_strdup(format);
	}

	/* A return value of 0 is either an error (in
	 * which case, the contents of the buffer are
	 * undefined) or the empty string (in which
	 * case, no harm is done here). */
	if ((len = purple_internal_strftime(buf, sizeof(buf), locale, tm)) == 0)
	{
		g_free(locale);
		return "";
	}

	g_free(locale);

	utf8 = g_locale_to_utf8(buf, len, NULL, NULL, &err);
	if (err != NULL)
	{
		purple_debug_error("util", "Result conversion failed in purple_utf8_strftime(): %s\n", err->message);
		g_error_free(err);
	}
	else
	{
		purple_strlcpy(buf, utf8);
		g_free(utf8);
	}

	return buf;
}

const char *
purple_date_format_short(const struct tm *tm)
{
	return purple_utf8_strftime("%x", tm);
}

const char *
purple_date_format_long(const struct tm *tm)
{
	/*
	 * This string determines how some dates are displayed.  The default
	 * string "%x %X" shows the date then the time.  Translators can
	 * change this to "%X %x" if they want the time to be shown first,
	 * followed by the date.
	 */
	return purple_utf8_strftime(_("%x %X"), tm);
}

const char *
purple_date_format_full(const struct tm *tm)
{
	return purple_utf8_strftime("%c", tm);
}

const char *
purple_time_format(const struct tm *tm)
{
	return purple_utf8_strftime("%X", tm);
}

time_t
purple_time_build(int year, int month, int day, int hour, int min, int sec)
{
	struct tm tm;

	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec >= 0 ? sec : time(NULL) % 60;

	return mktime(&tm);
}

/* originally taken from GLib trunk 1-6-11 */
/* originally licensed as LGPL 2+ */
static time_t
mktime_utc(struct tm *tm)
{
	time_t retval;

#ifndef HAVE_TIMEGM
	static const gint days_before[] =
	{
		0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
	};
#endif

#ifndef HAVE_TIMEGM
	if (tm->tm_mon < 0 || tm->tm_mon > 11)
		return (time_t) -1;

	retval = (tm->tm_year - 70) * 365;
	retval += (tm->tm_year - 68) / 4;
	retval += days_before[tm->tm_mon] + tm->tm_mday - 1;

	if (tm->tm_year % 4 == 0 && tm->tm_mon < 2)
		retval -= 1;

	retval = ((((retval * 24) + tm->tm_hour) * 60) + tm->tm_min) * 60 + tm->tm_sec;
#else
	retval = timegm (tm);
#endif /* !HAVE_TIMEGM */

	return retval;
}

time_t
purple_str_to_time(const char *timestamp, gboolean utc,
	struct tm *tm, long *tz_off, const char **rest)
{
	struct tm t;
	const gchar *str;
	gint year = 0;
	long tzoff = PURPLE_NO_TZ_OFF;
	time_t retval;
	gboolean mktime_with_utc = FALSE;

	if (rest != NULL)
		*rest = NULL;

	g_return_val_if_fail(timestamp != NULL, 0);

	memset(&t, 0, sizeof(struct tm));

	str = timestamp;

	/* Strip leading whitespace */
	while (g_ascii_isspace(*str))
		str++;

	if (*str == '\0') {
		if (rest != NULL && *str != '\0')
			*rest = str;

		return 0;
	}

	if (!g_ascii_isdigit(*str) && *str != '-' && *str != '+') {
		if (rest != NULL && *str != '\0')
			*rest = str;

		return 0;
	}

	/* 4 digit year */
	if (sscanf(str, "%04d", &year) && year >= 1900) {
		str += 4;

		if (*str == '-' || *str == '/')
			str++;

		t.tm_year = year - 1900;
	}

	/* 2 digit month */
	if (!sscanf(str, "%02d", &t.tm_mon)) {
		if (rest != NULL && *str != '\0')
			*rest = str;

		return 0;
	}

	str += 2;
	t.tm_mon -= 1;

	if (*str == '-' || *str == '/')
		str++;

	/* 2 digit day */
	if (!sscanf(str, "%02d", &t.tm_mday)) {
		if (rest != NULL && *str != '\0')
			*rest = str;

		return 0;
	}

	str += 2;

	/* Grab the year off the end if there's still stuff */
	if (*str == '/' || *str == '-') {
		/* But make sure we don't read the year twice */
		if (year >= 1900) {
			if (rest != NULL && *str != '\0')
				*rest = str;

			return 0;
		}

		str++;

		if (!sscanf(str, "%04d", &t.tm_year)) {
			if (rest != NULL && *str != '\0')
				*rest = str;

			return 0;
		}

		t.tm_year -= 1900;
	} else if (*str == 'T' || *str == '.') {
		str++;

		/* Continue grabbing the hours/minutes/seconds */
		if ((sscanf(str, "%02d:%02d:%02d", &t.tm_hour, &t.tm_min, &t.tm_sec) == 3 &&
				(str += 8)) ||
		    (sscanf(str, "%02d%02d%02d", &t.tm_hour, &t.tm_min, &t.tm_sec) == 3 &&
				(str += 6)))
		{
			gint sign, tzhrs, tzmins;

			if (*str == '.') {
				/* Cut off those pesky micro-seconds */
				do {
					str++;
				} while (*str >= '0' && *str <= '9');
			}

			sign = (*str == '+') ? 1 : -1;

			/* Process the timezone */
			if (*str == '+' || *str == '-') {
				str++;

				if (((sscanf(str, "%02d:%02d", &tzhrs, &tzmins) == 2 && (str += 5)) ||
					(sscanf(str, "%02d%02d", &tzhrs, &tzmins) == 2 && (str += 4))))
				{
					mktime_with_utc = TRUE;
					tzoff = tzhrs * 60 * 60 + tzmins * 60;
					tzoff *= sign;
				}
			} else if (*str == 'Z') {
				/* 'Z' = Zulu = UTC */
				str++;
				mktime_with_utc = TRUE;
				tzoff = 0;
			}

			if (!mktime_with_utc)
			{
				/* No timezone specified. */

				if (utc) {
					mktime_with_utc = TRUE;
					tzoff = 0;
				} else {
					/* Local Time */
					t.tm_isdst = -1;
				}
			}
		}
	}

	if (rest != NULL && *str != '\0') {
		/* Strip trailing whitespace */
		while (g_ascii_isspace(*str))
			str++;

		if (*str != '\0')
			*rest = str;
	}

	if (mktime_with_utc)
		retval = mktime_utc(&t);
	else
		retval = mktime(&t);

	if (tm != NULL)
		*tm = t;

	if (tzoff != PURPLE_NO_TZ_OFF)
		retval -= tzoff;

	if (tz_off != NULL)
		*tz_off = tzoff;

	return retval;
}

/**************************************************************************
 * Markup Functions
 **************************************************************************/

/*
 * This function is stolen from glib's gmarkup.c and modified to not
 * replace ' with &apos;
 */
static void append_escaped_text(GString *str,
		const gchar *text, gssize length)
{
	const gchar *p;
	const gchar *end;
	gunichar c;

	p = text;
	end = text + length;

	while (p != end)
	{
		const gchar *next;
		next = g_utf8_next_char (p);

		switch (*p)
		{
			case '&':
				g_string_append (str, "&amp;");
				break;

			case '<':
				g_string_append (str, "&lt;");
				break;

			case '>':
				g_string_append (str, "&gt;");
				break;

			case '"':
				g_string_append (str, "&quot;");
				break;

			default:
				c = g_utf8_get_char (p);
				if ((0x1 <= c && c <= 0x8) ||
						(0xb <= c && c <= 0xc) ||
						(0xe <= c && c <= 0x1f) ||
						(0x7f <= c && c <= 0x84) ||
						(0x86 <= c && c <= 0x9f))
					g_string_append_printf (str, "&#x%x;", c);
				else
					g_string_append_len (str, p, next - p);
				break;
		}

		p = next;
	}
}

/* This function is stolen from glib's gmarkup.c */
gchar *purple_markup_escape_text(const gchar *text, gssize length)
{
	GString *str;

	g_return_val_if_fail(text != NULL, NULL);

	if (length < 0)
		length = strlen(text);

	/* prealloc at least as long as original text */
	str = g_string_sized_new(length);
	append_escaped_text(str, text, length);

	return g_string_free(str, FALSE);
}

const char *
purple_markup_unescape_entity(const char *text, int *length)
{
	const char *pln;
	int len, pound;
	char temp[2];

	if (!text || *text != '&')
		return NULL;

#define IS_ENTITY(s)  (!g_ascii_strncasecmp(text, s, (len = sizeof(s) - 1)))

	if(IS_ENTITY("&amp;"))
		pln = "&";
	else if(IS_ENTITY("&lt;"))
		pln = "<";
	else if(IS_ENTITY("&gt;"))
		pln = ">";
	else if(IS_ENTITY("&nbsp;"))
		pln = " ";
	else if(IS_ENTITY("&copy;"))
		pln = "\302\251";      /* or use g_unichar_to_utf8(0xa9); */
	else if(IS_ENTITY("&quot;"))
		pln = "\"";
	else if(IS_ENTITY("&reg;"))
		pln = "\302\256";      /* or use g_unichar_to_utf8(0xae); */
	else if(IS_ENTITY("&apos;"))
		pln = "\'";
	else if(*(text+1) == '#' &&
			(sscanf(text, "&#%u%1[;]", &pound, temp) == 2 ||
			 sscanf(text, "&#x%x%1[;]", &pound, temp) == 2) &&
			pound != 0) {
		static char buf[7];
		int buflen = g_unichar_to_utf8((gunichar)pound, buf);
		buf[buflen] = '\0';
		pln = buf;

		len = (*(text+2) == 'x' ? 3 : 2);
		while(isxdigit((gint) text[len])) len++;
		if(text[len] == ';') len++;
	}
	else
		return NULL;

	if (length)
		*length = len;
	return pln;
}

char *
purple_markup_get_css_property(const gchar *style,
				const gchar *opt)
{
	const gchar *css_str = style;
	const gchar *css_value_start;
	const gchar *css_value_end;
	gchar *tmp;
	gchar *ret;

	g_return_val_if_fail(opt != NULL, NULL);

	if (!css_str)
		return NULL;

	/* find the CSS property */
	while (1)
	{
		/* skip whitespace characters */
		while (*css_str && g_ascii_isspace(*css_str))
			css_str++;
		if (!g_ascii_isalpha(*css_str))
			return NULL;
		if (g_ascii_strncasecmp(css_str, opt, strlen(opt)))
		{
			/* go to next css property positioned after the next ';' */
			while (*css_str && *css_str != '"' && *css_str != ';')
				css_str++;
			if(*css_str != ';')
				return NULL;
			css_str++;
		}
		else
			break;
	}

	/* find the CSS value position in the string */
	css_str += strlen(opt);
	while (*css_str && g_ascii_isspace(*css_str))
		css_str++;
	if (*css_str != ':')
		return NULL;
	css_str++;
	while (*css_str && g_ascii_isspace(*css_str))
		css_str++;
	if (*css_str == '\0' || *css_str == '"' || *css_str == ';')
		return NULL;

	/* mark the CSS value */
	css_value_start = css_str;
	while (*css_str && *css_str != '"' && *css_str != ';')
		css_str++;
	css_value_end = css_str - 1;

	/* Removes trailing whitespace */
	while (css_value_end > css_value_start && g_ascii_isspace(*css_value_end))
		css_value_end--;

	tmp = g_strndup(css_value_start, css_value_end - css_value_start + 1);
	ret = purple_unescape_html(tmp);
	g_free(tmp);

	return ret;
}

gboolean purple_markup_is_rtl(const char *html)
{
	GData *attributes;
	const gchar *start, *end;
	gboolean res = FALSE;

	if (purple_markup_find_tag("span", html, &start, &end, &attributes))
	{
		/* tmp is a member of attributes and is free with g_datalist_clear call */
		const char *tmp = g_datalist_get_data(&attributes, "dir");
		if (tmp && !g_ascii_strcasecmp(tmp, "RTL"))
			res = TRUE;
		if (!res)
		{
			tmp = g_datalist_get_data(&attributes, "style");
			if (tmp)
			{
				char *tmp2 = purple_markup_get_css_property(tmp, "direction");
				if (tmp2 && !g_ascii_strcasecmp(tmp2, "RTL"))
					res = TRUE;
				g_free(tmp2);
			}

		}
		g_datalist_clear(&attributes);
	}
	return res;
}

gboolean
purple_markup_find_tag(const char *needle, const char *haystack,
					 const char **start, const char **end, GData **attributes)
{
	GData *attribs;
	const char *cur = haystack;
	char *name = NULL;
	gboolean found = FALSE;
	gboolean in_tag = FALSE;
	gboolean in_attr = FALSE;
	const char *in_quotes = NULL;
	size_t needlelen;

	g_return_val_if_fail(    needle != NULL, FALSE);
	g_return_val_if_fail(   *needle != '\0', FALSE);
	g_return_val_if_fail(  haystack != NULL, FALSE);
	g_return_val_if_fail(     start != NULL, FALSE);
	g_return_val_if_fail(       end != NULL, FALSE);
	g_return_val_if_fail(attributes != NULL, FALSE);

	needlelen = strlen(needle);
	g_datalist_init(&attribs);

	while (*cur && !found) {
		if (in_tag) {
			if (in_quotes) {
				const char *close = cur;

				while (*close && *close != *in_quotes)
					close++;

				/* if we got the close quote, store the value and carry on from    *
				 * after it. if we ran to the end of the string, point to the NULL *
				 * and we're outta here */
				if (*close) {
					/* only store a value if we have an attribute name */
					if (name) {
						size_t len = close - cur;
						char *val = g_strndup(cur, len);

						g_datalist_set_data_full(&attribs, name, val, g_free);
						g_free(name);
						name = NULL;
					}

					in_quotes = NULL;
					cur = close + 1;
				} else {
					cur = close;
				}
			} else if (in_attr) {
				const char *close = cur;

				while (*close && *close != '>' && *close != '"' &&
						*close != '\'' && *close != ' ' && *close != '=')
					close++;

				/* if we got the equals, store the name of the attribute. if we got
				 * the quote, save the attribute and go straight to quote mode.
				 * otherwise the tag closed or we reached the end of the string,
				 * so we can get outta here */
				switch (*close) {
				case '"':
				case '\'':
					in_quotes = close;
				case '=':
					{
						size_t len = close - cur;

						/* don't store a blank attribute name */
						if (len) {
							g_free(name);
							name = g_ascii_strdown(cur, len);
						}

						in_attr = FALSE;
						cur = close + 1;
						break;
					}
				case ' ':
				case '>':
					in_attr = FALSE;
				default:
					cur = close;
					break;
				}
			} else {
				switch (*cur) {
				case ' ':
					/* swallow extra spaces inside tag */
					while (*cur && *cur == ' ') cur++;
					in_attr = TRUE;
					break;
				case '>':
					found = TRUE;
					*end = cur;
					break;
				case '"':
				case '\'':
					in_quotes = cur;
				default:
					cur++;
					break;
				}
			}
		} else {
			/* if we hit a < followed by the name of our tag... */
			if (*cur == '<' && !g_ascii_strncasecmp(cur + 1, needle, needlelen)) {
				*start = cur;
				cur = cur + needlelen + 1;

				/* if we're pointing at a space or a >, we found the right tag. if *
				 * we're not, we've found a longer tag, so we need to skip to the  *
				 * >, but not being distracted by >s inside quotes.                */
				if (*cur == ' ' || *cur == '>') {
					in_tag = TRUE;
				} else {
					while (*cur && *cur != '"' && *cur != '\'' && *cur != '>') {
						if (*cur == '"') {
							cur++;
							while (*cur && *cur != '"')
								cur++;
						} else if (*cur == '\'') {
							cur++;
							while (*cur && *cur != '\'')
								cur++;
						} else {
							cur++;
						}
					}
				}
			} else {
				cur++;
			}
		}
	}

	/* clean up any attribute name from a premature termination */
	g_free(name);

	if (found) {
		*attributes = attribs;
	} else {
		*start = NULL;
		*end = NULL;
		*attributes = NULL;
	}

	return found;
}

gboolean
purple_markup_extract_info_field(const char *str, int len, PurpleNotifyUserInfo *user_info,
							   const char *start_token, int skip,
							   const char *end_token, char check_value,
							   const char *no_value_token,
							   const char *display_name, gboolean is_link,
							   const char *link_prefix,
							   PurpleInfoFieldFormatCallback format_cb)
{
	const char *p, *q;

	g_return_val_if_fail(str          != NULL, FALSE);
	g_return_val_if_fail(user_info    != NULL, FALSE);
	g_return_val_if_fail(start_token  != NULL, FALSE);
	g_return_val_if_fail(end_token    != NULL, FALSE);
	g_return_val_if_fail(display_name != NULL, FALSE);

	p = strstr(str, start_token);

	if (p == NULL)
		return FALSE;

	p += strlen(start_token) + skip;

	if (p >= str + len)
		return FALSE;

	if (check_value != '\0' && *p == check_value)
		return FALSE;

	q = strstr(p, end_token);

	/* Trim leading blanks */
	while (*p != '\n' && g_ascii_isspace(*p)) {
		p += 1;
	}

	/* Trim trailing blanks */
	while (q > p && g_ascii_isspace(*(q - 1))) {
		q -= 1;
	}

	/* Don't bother with null strings */
	if (p == q)
		return FALSE;

	if (q != NULL && (!no_value_token ||
					  (no_value_token && strncmp(p, no_value_token,
												 strlen(no_value_token)))))
	{
		GString *dest = g_string_new("");

		if (is_link)
		{
			g_string_append(dest, "<a href=\"");

			if (link_prefix)
				g_string_append(dest, link_prefix);

			if (format_cb != NULL)
			{
				char *reformatted = format_cb(p, q - p);
				g_string_append(dest, reformatted);
				g_free(reformatted);
			}
			else
				g_string_append_len(dest, p, q - p);
			g_string_append(dest, "\">");

			if (link_prefix)
				g_string_append(dest, link_prefix);

			g_string_append_len(dest, p, q - p);
			g_string_append(dest, "</a>");
		}
		else
		{
			if (format_cb != NULL)
			{
				char *reformatted = format_cb(p, q - p);
				g_string_append(dest, reformatted);
				g_free(reformatted);
			}
			else
				g_string_append_len(dest, p, q - p);
		}

		purple_notify_user_info_add_pair(user_info, display_name, dest->str);
		g_string_free(dest, TRUE);

		return TRUE;
	}

	return FALSE;
}

struct purple_parse_tag {
	char *src_tag;
	char *dest_tag;
	gboolean ignore;
};

/* NOTE: Do not put `do {} while(0)` around this macro (as this is the method
         recommended in the GCC docs). It contains 'continue's that should
         affect the while-loop in purple_markup_html_to_xhtml and doing the
         above would break that.
         Also, remember to put braces in constructs that require them for
         multiple statements when using this macro. */
#define ALLOW_TAG_ALT(x, y) if(!g_ascii_strncasecmp(c, "<" x " ", strlen("<" x " "))) { \
						const char *o = c + strlen("<" x); \
						const char *p = NULL, *q = NULL, *r = NULL; \
						/* o = iterating over full tag \
						 * p = > (end of tag) \
						 * q = start of quoted bit \
						 * r = < inside tag \
						 */ \
						GString *innards = g_string_new(""); \
						while(o && *o) { \
							if(!q && (*o == '\"' || *o == '\'') ) { \
								q = o; \
							} else if(q) { \
								if(*o == *q) { /* end of quoted bit */ \
									char *unescaped = g_strndup(q+1, o-q-1); \
									char *escaped = g_markup_escape_text(unescaped, -1); \
									g_string_append_printf(innards, "%c%s%c", *q, escaped, *q); \
									g_free(unescaped); \
									g_free(escaped); \
									q = NULL; \
								} else if(*c == '\\') { \
									o++; \
								} \
							} else if(*o == '<') { \
								r = o; \
							} else if(*o == '>') { \
								p = o; \
								break; \
							} else { \
								innards = g_string_append_c(innards, *o); \
							} \
							o++; \
						} \
						if(p && !r) { /* got an end of tag and no other < earlier */\
							if(*(p-1) != '/') { \
								struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1); \
								pt->src_tag = x; \
								pt->dest_tag = y; \
								tags = g_list_prepend(tags, pt); \
							} \
							if(xhtml) { \
								xhtml = g_string_append(xhtml, "<" y); \
								xhtml = g_string_append(xhtml, innards->str); \
								xhtml = g_string_append_c(xhtml, '>'); \
							} \
							c = p + 1; \
						} else { /* got end of tag with earlier < *or* didn't get anything */ \
							if(xhtml) \
								xhtml = g_string_append(xhtml, "&lt;"); \
							if(plain) \
								plain = g_string_append_c(plain, '<'); \
							c++; \
						} \
						g_string_free(innards, TRUE); \
						continue; \
					} \
					if(!g_ascii_strncasecmp(c, "<" x, strlen("<" x)) && \
							(*(c+strlen("<" x)) == '>' || \
							 !g_ascii_strncasecmp(c+strlen("<" x), "/>", 2))) { \
						if(xhtml) \
							xhtml = g_string_append(xhtml, "<" y); \
						c += strlen("<" x); \
						if(*c != '/') { \
							struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1); \
							pt->src_tag = x; \
							pt->dest_tag = y; \
							tags = g_list_prepend(tags, pt); \
							if(xhtml) \
								xhtml = g_string_append_c(xhtml, '>'); \
						} else { \
							if(xhtml) \
								xhtml = g_string_append(xhtml, "/>");\
						} \
						c = strchr(c, '>') + 1; \
						continue; \
					}
/* Don't forget to check the note above for ALLOW_TAG_ALT. */
#define ALLOW_TAG(x) ALLOW_TAG_ALT(x, x)
void
purple_markup_html_to_xhtml(const char *html, char **xhtml_out,
						  char **plain_out)
{
	GString *xhtml = NULL;
	GString *plain = NULL;
	GString *url = NULL;
	GString *cdata = NULL;
	GList *tags = NULL, *tag;
	const char *c = html;
	char quote = '\0';

#define CHECK_QUOTE(ptr) if (*(ptr) == '\'' || *(ptr) == '\"') \
			quote = *(ptr++); \
		else \
			quote = '\0';

#define VALID_CHAR(ptr) (*(ptr) && *(ptr) != quote && (quote || (*(ptr) != ' ' && *(ptr) != '>')))

	g_return_if_fail(xhtml_out != NULL || plain_out != NULL);

	if(xhtml_out)
		xhtml = g_string_new("");
	if(plain_out)
		plain = g_string_new("");

	while(c && *c) {
		if(*c == '<') {
			if(*(c+1) == '/') { /* closing tag */
				tag = tags;
				while(tag) {
					struct purple_parse_tag *pt = tag->data;
					if(!g_ascii_strncasecmp((c+2), pt->src_tag, strlen(pt->src_tag)) && *(c+strlen(pt->src_tag)+2) == '>') {
						c += strlen(pt->src_tag) + 3;
						break;
					}
					tag = tag->next;
				}
				if(tag) {
					while(tags) {
						struct purple_parse_tag *pt = tags->data;
						if(xhtml && !pt->ignore)
							g_string_append_printf(xhtml, "</%s>", pt->dest_tag);
						if(plain && purple_strequal(pt->src_tag, "a")) {
							/* if this is a link, we have to add the url to the plaintext, too */
							if (cdata && url &&
									(!g_string_equal(cdata, url) && (g_ascii_strncasecmp(url->str, "mailto:", 7) != 0 ||
									                                 g_utf8_collate(url->str + 7, cdata->str) != 0)))
								g_string_append_printf(plain, " <%s>", g_strstrip(url->str));
							if (cdata) {
								g_string_free(cdata, TRUE);
								cdata = NULL;
							}

						}
						if(tags == tag)
							break;
						tags = g_list_remove(tags, pt);
						g_free(pt);
					}
					g_free(tag->data);
					tags = g_list_remove(tags, tag->data);
				} else {
					/* a closing tag we weren't expecting...
					 * we'll let it slide, if it's really a tag...if it's
					 * just a </ we'll escape it properly */
					const char *end = c+2;
					while(*end && g_ascii_isalpha(*end))
						end++;
					if(*end == '>') {
						c = end+1;
					} else {
						if(xhtml)
							xhtml = g_string_append(xhtml, "&lt;");
						if(plain)
							plain = g_string_append_c(plain, '<');
						c++;
					}
				}
			} else { /* opening tag */
				ALLOW_TAG("blockquote");
				ALLOW_TAG("cite");
				ALLOW_TAG("div");
				ALLOW_TAG("em");
				ALLOW_TAG("h1");
				ALLOW_TAG("h2");
				ALLOW_TAG("h3");
				ALLOW_TAG("h4");
				ALLOW_TAG("h5");
				ALLOW_TAG("h6");
				/* we only allow html to start the message */
				if(c == html) {
					ALLOW_TAG("html");
				}
				ALLOW_TAG_ALT("i", "em");
				ALLOW_TAG_ALT("italic", "em");
				ALLOW_TAG("li");
				ALLOW_TAG("ol");
				ALLOW_TAG("p");
				ALLOW_TAG("pre");
				ALLOW_TAG("q");
				ALLOW_TAG("span");
				ALLOW_TAG("ul");


				/* we skip <HR> because it's not legal in XHTML-IM.  However,
				 * we still want to send something sensible, so we put a
				 * linebreak in its place. <BR> also needs special handling
				 * because putting a </BR> to close it would just be dumb. */
				if((!g_ascii_strncasecmp(c, "<br", 3)
							|| !g_ascii_strncasecmp(c, "<hr", 3))
						&& (*(c+3) == '>' ||
							!g_ascii_strncasecmp(c+3, "/>", 2) ||
							!g_ascii_strncasecmp(c+3, " />", 3))) {
					c = strchr(c, '>') + 1;
					if(xhtml)
						xhtml = g_string_append(xhtml, "<br/>");
					if(plain && *c != '\n')
						plain = g_string_append_c(plain, '\n');
					continue;
				}
				if(!g_ascii_strncasecmp(c, "<b>", 3) || !g_ascii_strncasecmp(c, "<bold>", strlen("<bold>")) || !g_ascii_strncasecmp(c, "<strong>", strlen("<strong>"))) {
					struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1);
					if (*(c+2) == '>')
						pt->src_tag = "b";
					else if (*(c+2) == 'o')
						pt->src_tag = "bold";
					else
						pt->src_tag = "strong";
					pt->dest_tag = "span";
					tags = g_list_prepend(tags, pt);
					c = strchr(c, '>') + 1;
					if(xhtml)
						xhtml = g_string_append(xhtml, "<span style='font-weight: bold;'>");
					continue;
				}
				if(!g_ascii_strncasecmp(c, "<u>", 3) || !g_ascii_strncasecmp(c, "<underline>", strlen("<underline>"))) {
					struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1);
					pt->src_tag = *(c+2) == '>' ? "u" : "underline";
					pt->dest_tag = "span";
					tags = g_list_prepend(tags, pt);
					c = strchr(c, '>') + 1;
					if (xhtml)
						xhtml = g_string_append(xhtml, "<span style='text-decoration: underline;'>");
					continue;
				}
				if(!g_ascii_strncasecmp(c, "<s>", 3) || !g_ascii_strncasecmp(c, "<strike>", strlen("<strike>"))) {
					struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1);
					pt->src_tag = *(c+2) == '>' ? "s" : "strike";
					pt->dest_tag = "span";
					tags = g_list_prepend(tags, pt);
					c = strchr(c, '>') + 1;
					if(xhtml)
						xhtml = g_string_append(xhtml, "<span style='text-decoration: line-through;'>");
					continue;
				}
				if(!g_ascii_strncasecmp(c, "<sub>", 5)) {
					struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1);
					pt->src_tag = "sub";
					pt->dest_tag = "span";
					tags = g_list_prepend(tags, pt);
					c = strchr(c, '>') + 1;
					if(xhtml)
						xhtml = g_string_append(xhtml, "<span style='vertical-align:sub;'>");
					continue;
				}
				if(!g_ascii_strncasecmp(c, "<sup>", 5)) {
					struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1);
					pt->src_tag = "sup";
					pt->dest_tag = "span";
					tags = g_list_prepend(tags, pt);
					c = strchr(c, '>') + 1;
					if(xhtml)
						xhtml = g_string_append(xhtml, "<span style='vertical-align:super;'>");
					continue;
				}
				if (!g_ascii_strncasecmp(c, "<img", 4) && (*(c+4) == '>' || *(c+4) == ' ')) {
					const char *p = c + 4;
					GString *src = NULL, *alt = NULL;
					while (*p && *p != '>') {
						if (!g_ascii_strncasecmp(p, "src=", 4)) {
							const char *q = p + 4;
							if (src)
								g_string_free(src, TRUE);
							src = g_string_new("");
							CHECK_QUOTE(q);
							while (VALID_CHAR(q)) {
								src = g_string_append_c(src, *q);
								q++;
							}
							p = q;
						} else if (!g_ascii_strncasecmp(p, "alt=", 4)) {
							const char *q = p + 4;
							if (alt)
								g_string_free(alt, TRUE);
							alt = g_string_new("");
							CHECK_QUOTE(q);
							while (VALID_CHAR(q)) {
								alt = g_string_append_c(alt, *q);
								q++;
							}
							p = q;
						} else {
							p++;
						}
					}
					if ((c = strchr(p, '>')) != NULL)
						c++;
					else
						c = p;
					/* src and alt are required! */
					if(src && xhtml)
						g_string_append_printf(xhtml, "<img src='%s' alt='%s' />", g_strstrip(src->str), alt ? alt->str : "");
					if(alt) {
						if(plain)
							plain = g_string_append(plain, alt->str);
						if(!src && xhtml)
							xhtml = g_string_append(xhtml, alt->str);
						g_string_free(alt, TRUE);
					}
					g_string_free(src, TRUE);
					continue;
				}
				if (!g_ascii_strncasecmp(c, "<a", 2) && (*(c+2) == '>' || *(c+2) == ' ')) {
					const char *p = c + 2;
					struct purple_parse_tag *pt;
					while (*p && *p != '>') {
						if (!g_ascii_strncasecmp(p, "href=", 5)) {
							const char *q = p + 5;
							if (url)
								g_string_free(url, TRUE);
							url = g_string_new("");
							if (cdata)
								g_string_free(cdata, TRUE);
							cdata = g_string_new("");
							CHECK_QUOTE(q);
							while (VALID_CHAR(q)) {
								int len;
								if ((*q == '&') && (purple_markup_unescape_entity(q, &len) == NULL))
									url = g_string_append(url, "&amp;");
								else
									url = g_string_append_c(url, *q);
								q++;
							}
							p = q;
						} else {
							p++;
						}
					}
					if ((c = strchr(p, '>')) != NULL)
						c++;
					else
						c = p;
					pt = g_new0(struct purple_parse_tag, 1);
					pt->src_tag = "a";
					pt->dest_tag = "a";
					tags = g_list_prepend(tags, pt);
					if(xhtml)
						g_string_append_printf(xhtml, "<a href=\"%s\">", url ? g_strstrip(url->str) : "");
					continue;
				}
				if(!g_ascii_strncasecmp(c, "<font", 5) && (*(c+5) == '>' || *(c+5) == ' ')) {
					const char *p = c + 5;
					GString *style = g_string_new("");
					struct purple_parse_tag *pt;
					while (*p && *p != '>') {
						if (!g_ascii_strncasecmp(p, "back=", 5)) {
							const char *q = p + 5;
							GString *color = g_string_new("");
							CHECK_QUOTE(q);
							while (VALID_CHAR(q)) {
								color = g_string_append_c(color, *q);
								q++;
							}
							g_string_append_printf(style, "background: %s; ", color->str);
							g_string_free(color, TRUE);
							p = q;
						} else if (!g_ascii_strncasecmp(p, "color=", 6)) {
							const char *q = p + 6;
							GString *color = g_string_new("");
							CHECK_QUOTE(q);
							while (VALID_CHAR(q)) {
								color = g_string_append_c(color, *q);
								q++;
							}
							g_string_append_printf(style, "color: %s; ", color->str);
							g_string_free(color, TRUE);
							p = q;
						} else if (!g_ascii_strncasecmp(p, "face=", 5)) {
							const char *q = p + 5;
							GString *face = g_string_new("");
							CHECK_QUOTE(q);
							while (VALID_CHAR(q)) {
								face = g_string_append_c(face, *q);
								q++;
							}
							g_string_append_printf(style, "font-family: %s; ", g_strstrip(face->str));
							g_string_free(face, TRUE);
							p = q;
						} else if (!g_ascii_strncasecmp(p, "size=", 5)) {
							const char *q = p + 5;
							int sz;
							const char *size = "medium";
							CHECK_QUOTE(q);
							sz = atoi(q);
							switch (sz)
							{
							case 1:
							  size = "xx-small";
							  break;
							case 2:
							  size = "small";
							  break;
							case 3:
							  size = "medium";
							  break;
							case 4:
							  size = "large";
							  break;
							case 5:
							  size = "x-large";
							  break;
							case 6:
							case 7:
							  size = "xx-large";
							  break;
							default:
							  break;
							}
							g_string_append_printf(style, "font-size: %s; ", size);
							p = q;
						} else {
							p++;
						}
					}
					if ((c = strchr(p, '>')) != NULL)
						c++;
					else
						c = p;
					pt = g_new0(struct purple_parse_tag, 1);
					pt->src_tag = "font";
					pt->dest_tag = "span";
					tags = g_list_prepend(tags, pt);
					if(style->len && xhtml)
						g_string_append_printf(xhtml, "<span style='%s'>", g_strstrip(style->str));
					else
						pt->ignore = TRUE;
					g_string_free(style, TRUE);
					continue;
				}
				if (!g_ascii_strncasecmp(c, "<body ", 6)) {
					const char *p = c + 6;
					gboolean did_something = FALSE;
					while (*p && *p != '>') {
						if (!g_ascii_strncasecmp(p, "bgcolor=", 8)) {
							const char *q = p + 8;
							struct purple_parse_tag *pt = g_new0(struct purple_parse_tag, 1);
							GString *color = g_string_new("");
							CHECK_QUOTE(q);
							while (VALID_CHAR(q)) {
								color = g_string_append_c(color, *q);
								q++;
							}
							if (xhtml)
								g_string_append_printf(xhtml, "<span style='background: %s;'>", g_strstrip(color->str));
							g_string_free(color, TRUE);
							if ((c = strchr(p, '>')) != NULL)
								c++;
							else
								c = p;
							pt->src_tag = "body";
							pt->dest_tag = "span";
							tags = g_list_prepend(tags, pt);
							did_something = TRUE;
							break;
						}
						p++;
					}
					if (did_something) continue;
				}
				/* this has to come after the special case for bgcolor */
				ALLOW_TAG("body");
				if(!g_ascii_strncasecmp(c, "<!--", strlen("<!--"))) {
					char *p = strstr(c + strlen("<!--"), "-->");
					if(p) {
						if(xhtml)
							xhtml = g_string_append(xhtml, "<!--");
						c += strlen("<!--");
						continue;
					}
				}

				if(xhtml)
					xhtml = g_string_append(xhtml, "&lt;");
				if(plain)
					plain = g_string_append_c(plain, '<');
				c++;
			}
		} else if(*c == '&') {
			char buf[7];
			const char *pln;
			int len;

			if ((pln = purple_markup_unescape_entity(c, &len)) == NULL) {
				len = 1;
				g_snprintf(buf, sizeof(buf), "%c", *c);
				pln = buf;
			}
			if(xhtml)
				xhtml = g_string_append_len(xhtml, c, len);
			if(plain)
				plain = g_string_append(plain, pln);
			if(cdata)
				cdata = g_string_append_len(cdata, c, len);
			c += len;
		} else {
			if(xhtml)
				xhtml = g_string_append_c(xhtml, *c);
			if(plain)
				plain = g_string_append_c(plain, *c);
			if(cdata)
				cdata = g_string_append_c(cdata, *c);
			c++;
		}
	}
	if(xhtml) {
		for (tag = tags; tag ; tag = tag->next) {
			struct purple_parse_tag *pt = tag->data;
			if(!pt->ignore)
				g_string_append_printf(xhtml, "</%s>", pt->dest_tag);
		}
	}
	g_list_free(tags);
	if(xhtml_out)
		*xhtml_out = g_string_free(xhtml, FALSE);
	if(plain_out)
		*plain_out = g_string_free(plain, FALSE);
	if(url)
		g_string_free(url, TRUE);
	if (cdata)
		g_string_free(cdata, TRUE);
#undef CHECK_QUOTE
#undef VALID_CHAR
}

/* The following are probably reasonable changes:
 * - \n should be converted to a normal space
 * - in addition to <br>, <p> and <div> etc. should also be converted into \n
 * - We want to turn </td>#whitespace<td> sequences into a single tab
 * - We want to turn <td> into a single tab (for msn profile "parsing")
 * - We want to turn </tr>#whitespace<tr> sequences into a single \n
 * - <script>...</script> and <style>...</style> should be completely removed
 */

char *
purple_markup_strip_html(const char *str)
{
	int i, j, k, entlen;
	gboolean visible = TRUE;
	gboolean closing_td_p = FALSE;
	gchar *str2;
	const gchar *cdata_close_tag = NULL, *ent;
	gchar *href = NULL;
	int href_st = 0;

	if(!str)
		return NULL;

	str2 = g_strdup(str);

	for (i = 0, j = 0; str2[i]; i++)
	{
		if (str2[i] == '<')
		{
			if (cdata_close_tag)
			{
				/* Note: Don't even assume any other tag is a tag in CDATA */
				if (g_ascii_strncasecmp(str2 + i, cdata_close_tag,
						strlen(cdata_close_tag)) == 0)
				{
					i += strlen(cdata_close_tag) - 1;
					cdata_close_tag = NULL;
				}
				continue;
			}
			else if (g_ascii_strncasecmp(str2 + i, "<td", 3) == 0 && closing_td_p)
			{
				str2[j++] = '\t';
				visible = TRUE;
			}
			else if (g_ascii_strncasecmp(str2 + i, "</td>", 5) == 0)
			{
				closing_td_p = TRUE;
				visible = FALSE;
			}
			else
			{
				closing_td_p = FALSE;
				visible = TRUE;
			}

			k = i + 1;

			if(g_ascii_isspace(str2[k]))
				visible = TRUE;
			else if (str2[k])
			{
				/* Scan until we end the tag either implicitly (closed start
				 * tag) or explicitly, using a sloppy method (i.e., < or >
				 * inside quoted attributes will screw us up)
				 */
				while (str2[k] && str2[k] != '<' && str2[k] != '>')
				{
					k++;
				}

				/* If we've got an <a> tag with an href, save the address
				 * to print later. */
				if (g_ascii_strncasecmp(str2 + i, "<a", 2) == 0 &&
				    g_ascii_isspace(str2[i+2]))
				{
					int st; /* start of href, inclusive [ */
					int end; /* end of href, exclusive ) */
					char delim = ' ';
					/* Find start of href */
					for (st = i + 3; st < k; st++)
					{
						if (g_ascii_strncasecmp(str2+st, "href=", 5) == 0)
						{
							st += 5;
							if (str2[st] == '"' || str2[st] == '\'')
							{
								delim = str2[st];
								st++;
							}
							break;
						}
					}
					/* find end of address */
					for (end = st; end < k && str2[end] != delim; end++)
					{
						/* All the work is done in the loop construct above. */
					}

					/* If there's an address, save it.  If there was
					 * already one saved, kill it. */
					if (st < k)
					{
						char *tmp;
						g_free(href);
						tmp = g_strndup(str2 + st, end - st);
						href = purple_unescape_html(tmp);
						g_free(tmp);
						href_st = j;
					}
				}

				/* Replace </a> with an ascii representation of the
				 * address the link was pointing to. */
				else if (href != NULL && g_ascii_strncasecmp(str2 + i, "</a>", 4) == 0)
				{

					size_t hrlen = strlen(href);

					/* Only insert the href if it's different from the CDATA. */
					if ((hrlen != j - href_st ||
					     strncmp(str2 + href_st, href, hrlen)) &&
					    (hrlen != j - href_st + 7 || /* 7 == strlen("http://") */
					     strncmp(str2 + href_st, href + 7, hrlen - 7)))
					{
						str2[j++] = ' ';
						str2[j++] = '(';
						g_memmove(str2 + j, href, hrlen);
						j += hrlen;
						str2[j++] = ')';
						g_free(href);
						href = NULL;
					}
				}

				/* Check for tags which should be mapped to newline (but ignore some of
				 * the tags at the beginning of the text) */
				else if ((j && (g_ascii_strncasecmp(str2 + i, "<p>", 3) == 0
				              || g_ascii_strncasecmp(str2 + i, "<tr", 3) == 0
				              || g_ascii_strncasecmp(str2 + i, "<hr", 3) == 0
				              || g_ascii_strncasecmp(str2 + i, "<li", 3) == 0
				              || g_ascii_strncasecmp(str2 + i, "<div", 4) == 0))
				 || g_ascii_strncasecmp(str2 + i, "<br", 3) == 0
				 || g_ascii_strncasecmp(str2 + i, "</table>", 8) == 0)
				{
					str2[j++] = '\n';
				}
				/* Check for tags which begin CDATA and need to be closed */
#if 0 /* FIXME.. option is end tag optional, we can't handle this right now */
				else if (g_ascii_strncasecmp(str2 + i, "<option", 7) == 0)
				{
					/* FIXME: We should not do this if the OPTION is SELECT'd */
					cdata_close_tag = "</option>";
				}
#endif
				else if (g_ascii_strncasecmp(str2 + i, "<script", 7) == 0)
				{
					cdata_close_tag = "</script>";
				}
				else if (g_ascii_strncasecmp(str2 + i, "<style", 6) == 0)
				{
					cdata_close_tag = "</style>";
				}
				/* Update the index and continue checking after the tag */
				i = (str2[k] == '<' || str2[k] == '\0')? k - 1: k;
				continue;
			}
		}
		else if (cdata_close_tag)
		{
			continue;
		}
		else if (!g_ascii_isspace(str2[i]))
		{
			visible = TRUE;
		}

		if (str2[i] == '&' && (ent = purple_markup_unescape_entity(str2 + i, &entlen)) != NULL)
		{
			while (*ent)
				str2[j++] = *ent++;
			i += entlen - 1;
			continue;
		}

		if (visible)
			str2[j++] = g_ascii_isspace(str2[i])? ' ': str2[i];
	}

	g_free(href);

	str2[j] = '\0';

	return str2;
}

static gboolean
badchar(char c)
{
	switch (c) {
	case ' ':
	case ',':
	case '\0':
	case '\n':
	case '\r':
	case '<':
	case '>':
	case '"':
		return TRUE;
	default:
		return FALSE;
	}
}

static gboolean
badentity(const char *c)
{
	if (!g_ascii_strncasecmp(c, "&lt;", 4) ||
		!g_ascii_strncasecmp(c, "&gt;", 4) ||
		!g_ascii_strncasecmp(c, "&quot;", 6)) {
		return TRUE;
	}
	return FALSE;
}

static const char *
process_link(GString *ret,
		const char *start, const char *c,
		int matchlen,
		const char *urlprefix,
		int inside_paren)
{
	char *url_buf, *tmpurlbuf;
	const char *t;

	for (t = c;; t++) {
		if (!badchar(*t) && !badentity(t))
			continue;

		if (t - c == matchlen)
			break;

		if (*t == ',' && *(t + 1) != ' ') {
			continue;
		}

		if (t > start && *(t - 1) == '.')
			t--;
		if (t > start && *(t - 1) == ')' && inside_paren > 0)
			t--;

		url_buf = g_strndup(c, t - c);
		tmpurlbuf = purple_unescape_html(url_buf);
		g_string_append_printf(ret, "<A HREF=\"%s%s\">%s</A>",
				urlprefix,
				tmpurlbuf, url_buf);
		g_free(tmpurlbuf);
		g_free(url_buf);
		return t;
	}

	return c;
}

char *
purple_markup_linkify(const char *text)
{
	const char *c, *t, *q = NULL;
	char *tmpurlbuf, *url_buf;
	gunichar g;
	gboolean inside_html = FALSE;
	int inside_paren = 0;
	GString *ret;

	if (text == NULL)
		return NULL;

	ret = g_string_new("");

	c = text;
	while (*c) {

		if(*c == '(' && !inside_html) {
			inside_paren++;
			ret = g_string_append_c(ret, *c);
			c++;
		}

		if(inside_html) {
			if(*c == '>') {
				inside_html = FALSE;
			} else if(!q && (*c == '\"' || *c == '\'')) {
				q = c;
			} else if(q) {
				if(*c == *q)
					q = NULL;
			}
		} else if(*c == '<') {
			inside_html = TRUE;
			if (!g_ascii_strncasecmp(c, "<A", 2)) {
				while (1) {
					if (!g_ascii_strncasecmp(c, "/A>", 3)) {
						inside_html = FALSE;
						break;
					}
					ret = g_string_append_c(ret, *c);
					c++;
					if (!(*c))
						break;
				}
			}
		} else if (!g_ascii_strncasecmp(c, "http://", 7)) {
			c = process_link(ret, text, c, 7, "", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "https://", 8)) {
			c = process_link(ret, text, c, 8, "", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "ftp://", 6)) {
			c = process_link(ret, text, c, 6, "", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "sftp://", 7)) {
			c = process_link(ret, text, c, 7, "", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "file://", 7)) {
			c = process_link(ret, text, c, 7, "", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "www.", 4) && c[4] != '.' && (c == text || badchar(c[-1]) || badentity(c-1))) {
			c = process_link(ret, text, c, 4, "http://", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "ftp.", 4) && c[4] != '.' && (c == text || badchar(c[-1]) || badentity(c-1))) {
			c = process_link(ret, text, c, 4, "ftp://", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "xmpp:", 5) && (c == text || badchar(c[-1]) || badentity(c-1))) {
			c = process_link(ret, text, c, 5, "", inside_paren);
		} else if (!g_ascii_strncasecmp(c, "mailto:", 7)) {
			t = c;
			while (1) {
				if (badchar(*t) || badentity(t)) {
					char *d;
					if (t - c == 7) {
						break;
					}
					if (t > text && *(t - 1) == '.')
						t--;
					if ((d = strstr(c + 7, "?")) != NULL && d < t)
						url_buf = g_strndup(c + 7, d - c - 7);
					else
						url_buf = g_strndup(c + 7, t - c - 7);
					if (!purple_email_is_valid(url_buf)) {
						g_free(url_buf);
						break;
					}
					g_free(url_buf);
					url_buf = g_strndup(c, t - c);
					tmpurlbuf = purple_unescape_html(url_buf);
					g_string_append_printf(ret, "<A HREF=\"%s\">%s</A>",
							  tmpurlbuf, url_buf);
					g_free(url_buf);
					g_free(tmpurlbuf);
					c = t;
					break;
				}
				t++;
			}
		} else if (c != text && (*c == '@')) {
			int flag;
			GString *gurl_buf = NULL;
			const char illegal_chars[] = "!@#$%^&*()[]{}/|\\<>\":;\r\n \0";

			if (strchr(illegal_chars,*(c - 1)) || strchr(illegal_chars, *(c + 1)))
				flag = 0;
			else {
				flag = 1;
				gurl_buf = g_string_new("");
			}

			t = c;
			while (flag) {
				/* iterate backwards grabbing the local part of an email address */
				g = g_utf8_get_char(t);
				if (badchar(*t) || (g >= 127) || (*t == '(') ||
					((*t == ';') && ((t > (text+2) && (!g_ascii_strncasecmp(t - 3, "&lt;", 4) ||
				                                       !g_ascii_strncasecmp(t - 3, "&gt;", 4))) ||
				                     (t > (text+4) && (!g_ascii_strncasecmp(t - 5, "&quot;", 6)))))) {
					/* local part will already be part of ret, strip it out */
					ret = g_string_truncate(ret, ret->len - (c - t));
					ret = g_string_append_unichar(ret, g);
					break;
				} else {
					g_string_prepend_unichar(gurl_buf, g);
					t = g_utf8_find_prev_char(text, t);
					if (t < text) {
						ret = g_string_assign(ret, "");
						break;
					}
				}
			}

			t = g_utf8_find_next_char(c, NULL);

			while (flag) {
				/* iterate forwards grabbing the domain part of an email address */
				g = g_utf8_get_char(t);
				if (badchar(*t) || (g >= 127) || (*t == ')') || badentity(t)) {
					char *d;

					url_buf = g_string_free(gurl_buf, FALSE);

					/* strip off trailing periods */
					if (strlen(url_buf) > 0) {
						for (d = url_buf + strlen(url_buf) - 1; *d == '.'; d--, t--)
							*d = '\0';
					}

					tmpurlbuf = purple_unescape_html(url_buf);
					if (purple_email_is_valid(tmpurlbuf)) {
						g_string_append_printf(ret, "<A HREF=\"mailto:%s\">%s</A>",
								tmpurlbuf, url_buf);
					} else {
						g_string_append(ret, url_buf);
					}
					g_free(url_buf);
					g_free(tmpurlbuf);
					c = t;

					break;
				} else {
					g_string_append_unichar(gurl_buf, g);
					t = g_utf8_find_next_char(t, NULL);
				}
			}
		}

		if(*c == ')' && !inside_html) {
			inside_paren--;
			ret = g_string_append_c(ret, *c);
			c++;
		}

		if (*c == 0)
			break;

		ret = g_string_append_c(ret, *c);
		c++;

	}
	return g_string_free(ret, FALSE);
}

char *purple_unescape_text(const char *in)
{
    GString *ret;
    const char *c = in;

    if (in == NULL)
        return NULL;

    ret = g_string_new("");
    while (*c) {
        int len;
        const char *ent;

        if ((ent = purple_markup_unescape_entity(c, &len)) != NULL) {
            g_string_append(ret, ent);
            c += len;
        } else {
            g_string_append_c(ret, *c);
            c++;
        }
    }

    return g_string_free(ret, FALSE);
}

char *purple_unescape_html(const char *html)
{
	GString *ret;
	const char *c = html;

	if (html == NULL)
		return NULL;

	ret = g_string_new("");
	while (*c) {
		int len;
		const char *ent;

		if ((ent = purple_markup_unescape_entity(c, &len)) != NULL) {
			g_string_append(ret, ent);
			c += len;
		} else if (!strncmp(c, "<br>", 4)) {
			g_string_append_c(ret, '\n');
			c += 4;
		} else {
			g_string_append_c(ret, *c);
			c++;
		}
	}

	return g_string_free(ret, FALSE);
}

char *
purple_markup_slice(const char *str, guint x, guint y)
{
	GString *ret;
	GQueue *q;
	guint z = 0;
	gboolean appended = FALSE;
	gunichar c;
	char *tag;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(x <= y, NULL);

	if (x == y)
		return g_strdup("");

	ret = g_string_new("");
	q = g_queue_new();

	while (*str && (z < y)) {
		c = g_utf8_get_char(str);

		if (c == '<') {
			char *end = strchr(str, '>');

			if (!end) {
				g_string_free(ret, TRUE);
				while ((tag = g_queue_pop_head(q)))
					g_free(tag);
				g_queue_free(q);
				return NULL;
			}

			if (!g_ascii_strncasecmp(str, "<img ", 5)) {
				z += strlen("[Image]");
			} else if (!g_ascii_strncasecmp(str, "<br", 3)) {
				z += 1;
			} else if (!g_ascii_strncasecmp(str, "<hr>", 4)) {
				z += strlen("\n---\n");
			} else if (!g_ascii_strncasecmp(str, "</", 2)) {
				/* pop stack */
				char *tmp;

				tmp = g_queue_pop_head(q);
				g_free(tmp);
				/* z += 0; */
			} else {
				/* push it unto the stack */
				char *tmp;

				tmp = g_strndup(str, end - str + 1);
				g_queue_push_head(q, tmp);
				/* z += 0; */
			}

			if (z >= x) {
				g_string_append_len(ret, str, end - str + 1);
			}

			str = end;
		} else if (c == '&') {
			char *end = strchr(str, ';');
			if (!end) {
				g_string_free(ret, TRUE);
				while ((tag = g_queue_pop_head(q)))
					g_free(tag);
				g_queue_free(q);

				return NULL;
			}

			if (z >= x)
				g_string_append_len(ret, str, end - str + 1);

			z++;
			str = end;
		} else {
			if (z == x && z > 0 && !appended) {
				GList *l = q->tail;

				while (l) {
					tag = l->data;
					g_string_append(ret, tag);
					l = l->prev;
				}
				appended = TRUE;
			}

			if (z >= x)
				g_string_append_unichar(ret, c);
			z++;
		}

		str = g_utf8_next_char(str);
	}

	while ((tag = g_queue_pop_head(q))) {
		char *name;

		name = purple_markup_get_tag_name(tag);
		g_string_append_printf(ret, "</%s>", name);
		g_free(name);
		g_free(tag);
	}

	g_queue_free(q);
	return g_string_free(ret, FALSE);
}

char *
purple_markup_get_tag_name(const char *tag)
{
	int i;
	g_return_val_if_fail(tag != NULL, NULL);
	g_return_val_if_fail(*tag == '<', NULL);

	for (i = 1; tag[i]; i++)
		if (tag[i] == '>' || tag[i] == ' ' || tag[i] == '/')
			break;

	return g_strndup(tag+1, i-1);
}

/**************************************************************************
 * Path/Filename Functions
 **************************************************************************/
const char *
purple_home_dir(void)
{
#ifndef _WIN32
	return g_get_home_dir();
#else
	return wpurple_data_dir();
#endif
}

/* Returns the argument passed to -c IFF it was present, or ~/.purple. */
const char *
purple_user_dir(void)
{
	if (custom_user_dir != NULL)
		return custom_user_dir;
	else if (!user_dir)
		user_dir = g_build_filename(purple_home_dir(), ".purple", NULL);

	return user_dir;
}

void purple_util_set_user_dir(const char *dir)
{
	g_free(custom_user_dir);

	if (dir != NULL && *dir)
		custom_user_dir = g_strdup(dir);
	else
		custom_user_dir = NULL;
}

int purple_build_dir (const char *path, int mode)
{
	return g_mkdir_with_parents(path, mode);
}

/*
 * This function is long and beautiful, like my--um, yeah.  Anyway,
 * it includes lots of error checking so as we don't overwrite
 * people's settings if there is a problem writing the new values.
 */
gboolean
purple_util_write_data_to_file(const char *filename, const char *data, gssize size)
{
	const char *user_dir = purple_user_dir();
	gchar *filename_full;
	gboolean ret = FALSE;

	g_return_val_if_fail(user_dir != NULL, FALSE);

	purple_debug_info("util", "Writing file %s to directory %s\n",
					filename, user_dir);

	/* Ensure the user directory exists */
	if (!g_file_test(user_dir, G_FILE_TEST_IS_DIR))
	{
		if (g_mkdir(user_dir, S_IRUSR | S_IWUSR | S_IXUSR) == -1)
		{
			purple_debug_error("util", "Error creating directory %s: %s\n",
							 user_dir, g_strerror(errno));
			return FALSE;
		}
	}

	filename_full = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", user_dir, filename);

	ret = purple_util_write_data_to_file_absolute(filename_full, data, size);

	g_free(filename_full);
	return ret;
}

gboolean
purple_util_write_data_to_file_absolute(const char *filename_full, const char *data, gssize size)
{
	gchar *filename_temp;
	FILE *file;
	size_t real_size, byteswritten;
	struct stat st;
#ifndef HAVE_FILENO
	int fd;
#endif

	purple_debug_info("util", "Writing file %s\n",
					filename_full);

	g_return_val_if_fail((size >= -1), FALSE);

	filename_temp = g_strdup_printf("%s.save", filename_full);

	/* Remove an old temporary file, if one exists */
	if (g_file_test(filename_temp, G_FILE_TEST_EXISTS))
	{
		if (g_unlink(filename_temp) == -1)
		{
			purple_debug_error("util", "Error removing old file "
					   "%s: %s\n",
					   filename_temp, g_strerror(errno));
		}
	}

	/* Open file */
	file = g_fopen(filename_temp, "wb");
	if (file == NULL)
	{
		purple_debug_error("util", "Error opening file %s for "
				   "writing: %s\n",
				   filename_temp, g_strerror(errno));
		g_free(filename_temp);
		return FALSE;
	}

	/* Write to file */
	real_size = (size == -1) ? strlen(data) : (size_t) size;
	byteswritten = fwrite(data, 1, real_size, file);

#ifdef HAVE_FILENO
	/* Apparently XFS (and possibly other filesystems) do not
	 * guarantee that file data is flushed before file metadata,
	 * so this procedure is insufficient without some flushage. */
	if (fflush(file) < 0) {
		purple_debug_error("util", "Error flushing %s: %s\n",
				   filename_temp, g_strerror(errno));
		g_free(filename_temp);
		fclose(file);
		return FALSE;
	}
	if (fsync(fileno(file)) < 0) {
		purple_debug_error("util", "Error syncing file contents for %s: %s\n",
				   filename_temp, g_strerror(errno));
		g_free(filename_temp);
		fclose(file);
		return FALSE;
	}
#endif

	/* Close file */
	if (fclose(file) != 0)
	{
		purple_debug_error("util", "Error closing file %s: %s\n",
				   filename_temp, g_strerror(errno));
		g_free(filename_temp);
		return FALSE;
	}

#ifndef HAVE_FILENO
	/* This is the same effect (we hope) as the HAVE_FILENO block
	 * above, but for systems without fileno(). */
	if ((fd = open(filename_temp, O_RDWR)) < 0) {
		purple_debug_error("util", "Error opening file %s for flush: %s\n",
				   filename_temp, g_strerror(errno));
		g_free(filename_temp);
		return FALSE;
	}
	if (fsync(fd) < 0) {
		purple_debug_error("util", "Error syncing %s: %s\n",
				   filename_temp, g_strerror(errno));
		g_free(filename_temp);
		close(fd);
		return FALSE;
	}
	if (close(fd) < 0) {
		purple_debug_error("util", "Error closing %s after sync: %s\n",
				   filename_temp, g_strerror(errno));
		g_free(filename_temp);
		return FALSE;
	}
#endif

	/* Ensure the file is the correct size */
	if (byteswritten != real_size)
	{
		purple_debug_error("util", "Error writing to file %s: Wrote %"
				   G_GSIZE_FORMAT " bytes "
				   "but should have written %" G_GSIZE_FORMAT
				   "; is your disk full?\n",
				   filename_temp, byteswritten, real_size);
		g_free(filename_temp);
		return FALSE;
	}
	/* Use stat to be absolutely sure. */
	if ((g_stat(filename_temp, &st) == -1) || (st.st_size != real_size))
	{
		purple_debug_error("util", "Error writing data to file %s: "
				   "Incomplete file written; is your disk "
				   "full?\n",
				   filename_temp);
		g_free(filename_temp);
		return FALSE;
	}

#ifndef _WIN32
	/* Set file permissions */
	if (chmod(filename_temp, S_IRUSR | S_IWUSR) == -1)
	{
		purple_debug_error("util", "Error setting permissions of file %s: %s\n",
						 filename_temp, g_strerror(errno));
	}
#endif

	/* Rename to the REAL name */
	if (g_rename(filename_temp, filename_full) == -1)
	{
		purple_debug_error("util", "Error renaming %s to %s: %s\n",
				   filename_temp, filename_full,
				   g_strerror(errno));
	}

	g_free(filename_temp);

	return TRUE;
}

xmlnode *
purple_util_read_xml_from_file(const char *filename, const char *description)
{
	return xmlnode_from_file(purple_user_dir(), filename, description, "util");
}

/*
 * Like mkstemp() but returns a file pointer, uses a pre-set template,
 * uses the semantics of tempnam() for the directory to use and allocates
 * the space for the filepath.
 *
 * Caller is responsible for closing the file and removing it when done,
 * as well as freeing the space pointed-to by "path" with g_free().
 *
 * Returns NULL on failure and cleans up after itself if so.
 */
static const char *purple_mkstemp_templ = {"purpleXXXXXX"};

FILE *
purple_mkstemp(char **fpath, gboolean binary)
{
	const gchar *tmpdir;
	int fd;
	FILE *fp = NULL;

	g_return_val_if_fail(fpath != NULL, NULL);

	if((tmpdir = (gchar*)g_get_tmp_dir()) != NULL) {
		if((*fpath = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", tmpdir, purple_mkstemp_templ)) != NULL) {
			fd = g_mkstemp(*fpath);
			if(fd == -1) {
				purple_debug(PURPLE_DEBUG_ERROR, "purple_mkstemp",
						   "Couldn't make \"%s\", error: %d\n",
						   *fpath, errno);
			} else {
				if((fp = fdopen(fd, "r+")) == NULL) {
					close(fd);
					purple_debug(PURPLE_DEBUG_ERROR, "purple_mkstemp",
							   "Couldn't fdopen(), error: %d\n", errno);
				}
			}

			if(!fp) {
				g_free(*fpath);
				*fpath = NULL;
			}
		}
	} else {
		purple_debug(PURPLE_DEBUG_ERROR, "purple_mkstemp",
				   "g_get_tmp_dir() failed!\n");
	}

	return fp;
}

const char *
purple_util_get_image_extension(gconstpointer data, size_t len)
{
	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(len   > 0,    NULL);

	if (len >= 4)
	{
		if (!strncmp((char *)data, "GIF8", 4))
			return "gif";
		else if (!strncmp((char *)data, "\xff\xd8\xff", 3)) /* 4th may be e0 through ef */
			return "jpg";
		else if (!strncmp((char *)data, "\x89PNG", 4))
			return "png";
		else if (!strncmp((char *)data, "MM", 2) ||
				 !strncmp((char *)data, "II", 2))
			return "tif";
		else if (!strncmp((char *)data, "BM", 2))
			return "bmp";
	}

	return "icon";
}

/*
 * We thought about using non-cryptographic hashes like CRC32 here.
 * They would be faster, but we think using something more secure is
 * important, so that it is more difficult for someone to maliciously
 * replace one buddy's icon with something else.
 */
char *
purple_util_get_image_checksum(gconstpointer image_data, size_t image_len)
{
	PurpleCipherContext *context;
	gchar digest[41];

	context = purple_cipher_context_new_by_name("sha1", NULL);
	if (context == NULL)
	{
		purple_debug_error("util", "Could not find sha1 cipher\n");
		g_return_val_if_reached(NULL);
	}

	/* Hash the image data */
	purple_cipher_context_append(context, image_data, image_len);
	if (!purple_cipher_context_digest_to_str(context, sizeof(digest), digest, NULL))
	{
		purple_debug_error("util", "Failed to get SHA-1 digest.\n");
		g_return_val_if_reached(NULL);
	}
	purple_cipher_context_destroy(context);

	return g_strdup(digest);
}

char *
purple_util_get_image_filename(gconstpointer image_data, size_t image_len)
{
	/* Return the filename */
	char *checksum = purple_util_get_image_checksum(image_data, image_len);
	char *filename = g_strdup_printf("%s.%s", checksum,
	                       purple_util_get_image_extension(image_data, image_len));
	g_free(checksum);
	return filename;
}

gboolean
purple_program_is_valid(const char *program)
{
	GError *error = NULL;
	char **argv;
	gchar *progname;
	gboolean is_valid = FALSE;

	g_return_val_if_fail(program != NULL,  FALSE);
	g_return_val_if_fail(*program != '\0', FALSE);

	if (!g_shell_parse_argv(program, NULL, &argv, &error)) {
		purple_debug(PURPLE_DEBUG_ERROR, "program_is_valid",
				   "Could not parse program '%s': %s\n",
				   program, error->message);
		g_error_free(error);
		return FALSE;
	}

	if (argv == NULL) {
		return FALSE;
	}

	progname = g_find_program_in_path(argv[0]);
	is_valid = (progname != NULL);

	if(purple_debug_is_verbose())
		purple_debug_info("program_is_valid", "Tested program %s.  %s.\n", program,
				is_valid ? "Valid" : "Invalid");

	g_strfreev(argv);
	g_free(progname);

	return is_valid;
}


gboolean
purple_running_gnome(void)
{
#ifndef _WIN32
	gchar *tmp = g_find_program_in_path("gnome-open");

	if (tmp == NULL)
		return FALSE;
	g_free(tmp);

	tmp = (gchar *)g_getenv("GNOME_DESKTOP_SESSION_ID");

	return ((tmp != NULL) && (*tmp != '\0'));
#else
	return FALSE;
#endif
}

gboolean
purple_running_kde(void)
{
#ifndef _WIN32
	gchar *tmp = g_find_program_in_path("kfmclient");
	const char *session;

	if (tmp == NULL)
		return FALSE;
	g_free(tmp);

	session = g_getenv("KDE_FULL_SESSION");
	if (purple_strequal(session, "true"))
		return TRUE;

	/* If you run Purple from Konsole under !KDE, this will provide a
	 * a false positive.  Since we do the GNOME checks first, this is
	 * only a problem if you're running something !(KDE || GNOME) and
	 * you run Purple from Konsole. This really shouldn't be a problem. */
	return ((g_getenv("KDEDIR") != NULL) || g_getenv("KDEDIRS") != NULL);
#else
	return FALSE;
#endif
}

gboolean
purple_running_osx(void)
{
#if defined(__APPLE__)
	return TRUE;
#else
	return FALSE;
#endif
}

typedef union purple_sockaddr {
	struct sockaddr         sa;
	struct sockaddr_in      sa_in;
#if defined(AF_INET6)
	struct sockaddr_in6     sa_in6;
#endif
	struct sockaddr_storage sa_stor;
} PurpleSockaddr;

char *
purple_fd_get_ip(int fd)
{
	PurpleSockaddr addr;
	socklen_t namelen = sizeof(addr);
	int family;

	g_return_val_if_fail(fd != 0, NULL);

	if (getsockname(fd, &(addr.sa), &namelen))
		return NULL;

	family = addr.sa.sa_family;

	if (family == AF_INET) {
		return g_strdup(inet_ntoa(addr.sa_in.sin_addr));
	}
#if defined(AF_INET6) && defined(HAVE_INET_NTOP)
	else if (family == AF_INET6) {
		char host[INET6_ADDRSTRLEN];
		const char *tmp;

		tmp = inet_ntop(family, &(addr.sa_in6.sin6_addr), host, sizeof(host));
		return g_strdup(tmp);
	}
#endif

	return NULL;
}

int
purple_socket_get_family(int fd)
{
	PurpleSockaddr addr;
	socklen_t len = sizeof(addr);

	g_return_val_if_fail(fd >= 0, -1);

	if (getsockname(fd, &(addr.sa), &len))
		return -1;

	return addr.sa.sa_family;
}

gboolean
purple_socket_speaks_ipv4(int fd)
{
	int family;

	g_return_val_if_fail(fd >= 0, FALSE);

	family = purple_socket_get_family(fd);

	switch (family) {
	case AF_INET:
		return TRUE;
#if defined(IPV6_V6ONLY)
	case AF_INET6:
	{
		int val = 0;
		guint len = sizeof(val);

		if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, &len) != 0)
			return FALSE;
		return !val;
	}
#endif
	default:
		return FALSE;
	}
}

/**************************************************************************
 * String Functions
 **************************************************************************/
gboolean
purple_strequal(const gchar *left, const gchar *right)
{
#if GLIB_CHECK_VERSION(2,16,0)
	return (g_strcmp0(left, right) == 0);
#else
	return ((left == NULL && right == NULL) ||
	        (left != NULL && right != NULL && strcmp(left, right) == 0));
#endif
}

const char *
purple_normalize(const PurpleAccount *account, const char *str)
{
	const char *ret = NULL;
	static char buf[BUF_LEN];

	/* This should prevent a crash if purple_normalize gets called with NULL str, see #10115 */
	g_return_val_if_fail(str != NULL, "");

	if (account != NULL)
	{
		PurplePlugin *prpl = purple_find_prpl(purple_account_get_protocol_id(account));

		if (prpl != NULL)
		{
			PurplePluginProtocolInfo *prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

			if (prpl_info->normalize)
				ret = prpl_info->normalize(account, str);
		}
	}

	if (ret == NULL)
	{
		char *tmp;

		tmp = g_utf8_normalize(str, -1, G_NORMALIZE_DEFAULT);
		g_snprintf(buf, sizeof(buf), "%s", tmp);
		g_free(tmp);

		ret = buf;
	}

	return ret;
}

/*
 * You probably don't want to call this directly, it is
 * mainly for use as a PRPL callback function.  See the
 * comments in util.h.
 */
const char *
purple_normalize_nocase(const PurpleAccount *account, const char *str)
{
	static char buf[BUF_LEN];
	char *tmp1, *tmp2;

	g_return_val_if_fail(str != NULL, NULL);

	tmp1 = g_utf8_strdown(str, -1);
	tmp2 = g_utf8_normalize(tmp1, -1, G_NORMALIZE_DEFAULT);
	g_snprintf(buf, sizeof(buf), "%s", tmp2 ? tmp2 : "");
	g_free(tmp2);
	g_free(tmp1);

	return buf;
}

gchar *
purple_strdup_withhtml(const gchar *src)
{
	gulong destsize, i, j;
	gchar *dest;

	g_return_val_if_fail(src != NULL, NULL);

	/* New length is (length of src) + (number of \n's * 3) - (number of \r's) + 1 */
	destsize = 1;
	for (i = 0; src[i] != '\0'; i++)
	{
		if (src[i] == '\n')
			destsize += 4;
		else if (src[i] != '\r')
			destsize++;
	}

	dest = g_malloc(destsize);

	/* Copy stuff, ignoring \r's, because they are dumb */
	for (i = 0, j = 0; src[i] != '\0'; i++) {
		if (src[i] == '\n') {
			strcpy(&dest[j], "<BR>");
			j += 4;
		} else if (src[i] != '\r')
			dest[j++] = src[i];
	}

	dest[destsize-1] = '\0';

	return dest;
}

gboolean
purple_str_has_prefix(const char *s, const char *p)
{
	return g_str_has_prefix(s, p);
}

gboolean
purple_str_has_suffix(const char *s, const char *x)
{
	return g_str_has_suffix(s, x);
}

char *
purple_str_add_cr(const char *text)
{
	char *ret = NULL;
	int count = 0, j;
	guint i;

	g_return_val_if_fail(text != NULL, NULL);

	if (text[0] == '\n')
		count++;
	for (i = 1; i < strlen(text); i++)
		if (text[i] == '\n' && text[i - 1] != '\r')
			count++;

	if (count == 0)
		return g_strdup(text);

	ret = g_malloc0(strlen(text) + count + 1);

	i = 0; j = 0;
	if (text[i] == '\n')
		ret[j++] = '\r';
	ret[j++] = text[i++];
	for (; i < strlen(text); i++) {
		if (text[i] == '\n' && text[i - 1] != '\r')
			ret[j++] = '\r';
		ret[j++] = text[i];
	}

	return ret;
}

void
purple_str_strip_char(char *text, char thechar)
{
	int i, j;

	g_return_if_fail(text != NULL);

	for (i = 0, j = 0; text[i]; i++)
		if (text[i] != thechar)
			text[j++] = text[i];

	text[j] = '\0';
}

void
purple_util_chrreplace(char *string, char delimiter,
					 char replacement)
{
	int i = 0;

	g_return_if_fail(string != NULL);

	while (string[i] != '\0')
	{
		if (string[i] == delimiter)
			string[i] = replacement;
		i++;
	}
}

gchar *
purple_strreplace(const char *string, const char *delimiter,
				const char *replacement)
{
	gchar **split;
	gchar *ret;

	g_return_val_if_fail(string      != NULL, NULL);
	g_return_val_if_fail(delimiter   != NULL, NULL);
	g_return_val_if_fail(replacement != NULL, NULL);

	split = g_strsplit(string, delimiter, 0);
	ret = g_strjoinv(replacement, split);
	g_strfreev(split);

	return ret;
}

gchar *
purple_strcasereplace(const char *string, const char *delimiter,
					const char *replacement)
{
	gchar *ret;
	int length_del, length_rep, i, j;

	g_return_val_if_fail(string      != NULL, NULL);
	g_return_val_if_fail(delimiter   != NULL, NULL);
	g_return_val_if_fail(replacement != NULL, NULL);

	length_del = strlen(delimiter);
	length_rep = strlen(replacement);

	/* Count how many times the delimiter appears */
	i = 0; /* position in the source string */
	j = 0; /* number of occurrences of "delimiter" */
	while (string[i] != '\0') {
		if (!g_ascii_strncasecmp(&string[i], delimiter, length_del)) {
			i += length_del;
			j += length_rep;
		} else {
			i++;
			j++;
		}
	}

	ret = g_malloc(j+1);

	i = 0; /* position in the source string */
	j = 0; /* position in the destination string */
	while (string[i] != '\0') {
		if (!g_ascii_strncasecmp(&string[i], delimiter, length_del)) {
			strncpy(&ret[j], replacement, length_rep);
			i += length_del;
			j += length_rep;
		} else {
			ret[j] = string[i];
			i++;
			j++;
		}
	}

	ret[j] = '\0';

	return ret;
}

/** TODO: Expose this when we can add API */
static const char *
purple_strcasestr_len(const char *haystack, gssize hlen, const char *needle, gssize nlen)
{
	const char *tmp, *ret;

	g_return_val_if_fail(haystack != NULL, NULL);
	g_return_val_if_fail(needle != NULL, NULL);

	if (hlen == -1)
		hlen = strlen(haystack);
	if (nlen == -1)
		nlen = strlen(needle);
	tmp = haystack,
	ret = NULL;

	g_return_val_if_fail(hlen > 0, NULL);
	g_return_val_if_fail(nlen > 0, NULL);

	while (*tmp && !ret && (hlen - (tmp - haystack)) >= nlen) {
		if (!g_ascii_strncasecmp(needle, tmp, nlen))
			ret = tmp;
		else
			tmp++;
	}

	return ret;
}

const char *
purple_strcasestr(const char *haystack, const char *needle)
{
	return purple_strcasestr_len(haystack, -1, needle, -1);
}

char *
purple_str_size_to_units(size_t size)
{
	static const char * const size_str[] = { "bytes", "KiB", "MiB", "GiB" };
	float size_mag;
	int size_index = 0;

	if (size == -1) {
		return g_strdup(_("Calculating..."));
	}
	else if (size == 0) {
		return g_strdup(_("Unknown."));
	}
	else {
		size_mag = (float)size;

		while ((size_index < 3) && (size_mag > 1024)) {
			size_mag /= 1024;
			size_index++;
		}

		if (size_index == 0) {
			return g_strdup_printf("%" G_GSIZE_FORMAT " %s", size, size_str[size_index]);
		} else {
			return g_strdup_printf("%.2f %s", size_mag, size_str[size_index]);
		}
	}
}

char *
purple_str_seconds_to_string(guint secs)
{
	char *ret = NULL;
	guint days, hrs, mins;

	if (secs < 60)
	{
		return g_strdup_printf(dngettext(PACKAGE, "%d second", "%d seconds", secs), secs);
	}

	days = secs / (60 * 60 * 24);
	secs = secs % (60 * 60 * 24);
	hrs  = secs / (60 * 60);
	secs = secs % (60 * 60);
	mins = secs / 60;
	secs = secs % 60;

	if (days > 0)
	{
		ret = g_strdup_printf(dngettext(PACKAGE, "%d day", "%d days", days), days);
	}

	if (hrs > 0)
	{
		if (ret != NULL)
		{
			char *tmp = g_strdup_printf(
					dngettext(PACKAGE, "%s, %d hour", "%s, %d hours", hrs),
							ret, hrs);
			g_free(ret);
			ret = tmp;
		}
		else
			ret = g_strdup_printf(dngettext(PACKAGE, "%d hour", "%d hours", hrs), hrs);
	}

	if (mins > 0)
	{
		if (ret != NULL)
		{
			char *tmp = g_strdup_printf(
					dngettext(PACKAGE, "%s, %d minute", "%s, %d minutes", mins),
							ret, mins);
			g_free(ret);
			ret = tmp;
		}
		else
			ret = g_strdup_printf(dngettext(PACKAGE, "%d minute", "%d minutes", mins), mins);
	}

	return ret;
}


char *
purple_str_binary_to_ascii(const unsigned char *binary, guint len)
{
	GString *ret;
	guint i;

	g_return_val_if_fail(len > 0, NULL);

	ret = g_string_sized_new(len);

	for (i = 0; i < len; i++)
		if (binary[i] < 32 || binary[i] > 126)
			g_string_append_printf(ret, "\\x%02hhx", binary[i]);
		else if (binary[i] == '\\')
			g_string_append(ret, "\\\\");
		else
			g_string_append_c(ret, binary[i]);

	return g_string_free(ret, FALSE);
}

/**************************************************************************
 * URI/URL Functions
 **************************************************************************/

void purple_got_protocol_handler_uri(const char *uri)
{
	char proto[11];
	char delimiter;
	const char *tmp, *param_string;
	char *cmd;
	GHashTable *params = NULL;
	int len;
	if (!(tmp = strchr(uri, ':')) || tmp == uri) {
		purple_debug_error("util", "Malformed protocol handler message - missing protocol.\n");
		return;
	}

	len = MIN(sizeof(proto) - 1, (tmp - uri));

	strncpy(proto, uri, len);
	proto[len] = '\0';

	tmp++;

	if (g_str_equal(proto, "xmpp"))
		delimiter = ';';
	else
		delimiter = '&';

	purple_debug_info("util", "Processing message '%s' for protocol '%s' using delimiter '%c'.\n", tmp, proto, delimiter);

	if ((param_string = strchr(tmp, '?'))) {
		const char *keyend = NULL, *pairstart;
		char *key, *value = NULL;

		cmd = g_strndup(tmp, (param_string - tmp));
		param_string++;

		params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		pairstart = tmp = param_string;

		while (*tmp || *pairstart) {
			if (*tmp == delimiter || !(*tmp)) {
				/* If there is no explicit value */
				if (keyend == NULL)
					keyend = tmp;

				if (keyend && keyend != pairstart) {
					char *p;
					key = g_strndup(pairstart, (keyend - pairstart));
					/* If there is an explicit value */
					if (keyend != tmp && keyend != (tmp - 1))
						value = g_strndup(keyend + 1, (tmp - keyend - 1));
					for (p = key; *p; ++p)
						*p = g_ascii_tolower(*p);
					g_hash_table_insert(params, key, value);
				}
				keyend = value = NULL;
				pairstart = (*tmp) ? tmp + 1 : tmp;
			} else if (*tmp == '=')
				keyend = tmp;

			if (*tmp)
				tmp++;
		}
	} else
		cmd = g_strdup(tmp);

	purple_signal_emit_return_1(purple_get_core(), "uri-handler", proto, cmd, params);

	g_free(cmd);
	if (params)
		g_hash_table_destroy(params);
}

/*
 * TODO: Should probably add a "gboolean *ret_ishttps" parameter that
 *       is set to TRUE if this URL is https, otherwise it is set to
 *       FALSE.  But that change will break the API.
 *
 *       This is important for Yahoo! web messenger login.  They now
 *       force https login, and if you access the web messenger login
 *       page via http then it redirects you to the https version, but
 *       purple_util_fetch_url() ignores the "https" and attempts to
 *       fetch the URL via http again, which gets redirected again.
 */
gboolean
purple_url_parse(const char *url, char **ret_host, int *ret_port,
			   char **ret_path, char **ret_user, char **ret_passwd)
{
	gboolean is_https = FALSE;
	const char * scan_info;
	char port_str[6];
	int f;
	const char *at, *slash;
	const char *turl;
	char host[256], path[256], user[256], passwd[256];
	int port = 0;
	/* hyphen at end includes it in control set */

#define ADDR_CTRL "A-Za-z0-9.-"
#define PORT_CTRL "0-9"
#define PAGE_CTRL "A-Za-z0-9.~_/:*!@&%%?=+^-"
#define USER_CTRL "A-Za-z0-9.~_/*!&%%?=+^-"
#define PASSWD_CTRL "A-Za-z0-9.~_/*!&%%?=+^-"

	g_return_val_if_fail(url != NULL, FALSE);

	if ((turl = purple_strcasestr(url, "http://")) != NULL)
	{
		turl += 7;
		url = turl;
	}
	else if ((turl = purple_strcasestr(url, "https://")) != NULL)
	{
		is_https = TRUE;
		turl += 8;
		url = turl;
	}

	/* parse out authentication information if supplied */
	/* Only care about @ char BEFORE the first / */
	at = strchr(url, '@');
	slash = strchr(url, '/');
	f = 0;
	if (at && (!slash || at < slash)) {
		scan_info = "%255[" USER_CTRL "]:%255[" PASSWD_CTRL "]^@";
		f = sscanf(url, scan_info, user, passwd);

		if (f == 1) {
			/* No passwd, possibly just username supplied */
			scan_info = "%255[" USER_CTRL "]^@";
			f = sscanf(url, scan_info, user);
		}

		url = at+1; /* move pointer after the @ char */
	}

	if (f < 1) {
		*user = '\0';
		*passwd = '\0';
	} else if (f == 1)
		*passwd = '\0';

	scan_info = "%255[" ADDR_CTRL "]:%5[" PORT_CTRL "]/%255[" PAGE_CTRL "]";
	f = sscanf(url, scan_info, host, port_str, path);

	if (f == 1)
	{
		scan_info = "%255[" ADDR_CTRL "]/%255[" PAGE_CTRL "]";
		f = sscanf(url, scan_info, host, path);
		/* Use the default port */
		if (is_https)
			g_snprintf(port_str, sizeof(port_str), "443");
		else
			g_snprintf(port_str, sizeof(port_str), "80");
	}

	if (f == 0)
		*host = '\0';

	if (f <= 1)
		*path = '\0';

	if (sscanf(port_str, "%d", &port) != 1)
		purple_debug_error("util", "Error parsing URL port from %s\n", url);

	if (ret_host != NULL) *ret_host = g_strdup(host);
	if (ret_port != NULL) *ret_port = port;
	if (ret_path != NULL) *ret_path = g_strdup(path);
	if (ret_user != NULL) *ret_user = g_strdup(user);
	if (ret_passwd != NULL) *ret_passwd = g_strdup(passwd);

	return ((*host != '\0') ? TRUE : FALSE);

#undef ADDR_CTRL
#undef PORT_CTRL
#undef PAGE_CTRL
#undef USER_CTRL
#undef PASSWD_CTRL
}

/**
 * The arguments to this function are similar to printf.
 */
static void
purple_util_fetch_url_error(PurpleUtilFetchUrlData *gfud, const char *format, ...)
{
	gchar *error_message;
	va_list args;

	va_start(args, format);
	error_message = g_strdup_vprintf(format, args);
	va_end(args);

	gfud->callback(gfud, gfud->user_data, NULL, 0, error_message);
	g_free(error_message);
	purple_util_fetch_url_cancel(gfud);
}

static void url_fetch_connect_cb(gpointer url_data, gint source, const gchar *error_message);
static void ssl_url_fetch_connect_cb(gpointer data, PurpleSslConnection *ssl_connection, PurpleInputCondition cond);
static void ssl_url_fetch_error_cb(PurpleSslConnection *ssl_connection, PurpleSslErrorType error, gpointer data);

static gboolean
parse_redirect(const char *data, gsize data_len,
			   PurpleUtilFetchUrlData *gfud)
{
	gchar *s;
	gchar *new_url, *temp_url, *end;
	gboolean full;
	int len;

	if ((s = g_strstr_len(data, data_len, "\nLocation: ")) == NULL)
		/* We're not being redirected */
		return FALSE;

	s += strlen("Location: ");
	end = strchr(s, '\r');

	/* Just in case :) */
	if (end == NULL)
		end = strchr(s, '\n');

	if (end == NULL)
		return FALSE;

	len = end - s;

	new_url = g_malloc(len + 1);
	strncpy(new_url, s, len);
	new_url[len] = '\0';

	full = gfud->full;

	if (*new_url == '/' || g_strstr_len(new_url, len, "://") == NULL)
	{
		temp_url = new_url;

		new_url = g_strdup_printf("%s:%d%s", gfud->website.address,
								  gfud->website.port, temp_url);

		g_free(temp_url);

		full = FALSE;
	}

	purple_debug_info("util", "Redirecting to %s\n", new_url);

	gfud->num_times_redirected++;
	if (gfud->num_times_redirected >= 5)
	{
		purple_util_fetch_url_error(gfud,
				_("Could not open %s: Redirected too many times"),
				gfud->url);
		return TRUE;
	}

	/*
	 * Try again, with this new location.  This code is somewhat
	 * ugly, but we need to reuse the gfud because whoever called
	 * us is holding a reference to it.
	 */
	g_free(gfud->url);
	gfud->url = new_url;
	gfud->full = full;
	g_free(gfud->request);
	gfud->request = NULL;

	if (gfud->is_ssl) {
		gfud->is_ssl = FALSE;
		purple_ssl_close(gfud->ssl_connection);
		gfud->ssl_connection = NULL;
	} else {
		purple_input_remove(gfud->inpa);
		gfud->inpa = 0;
		close(gfud->fd);
		gfud->fd = -1;
	}
	gfud->request_written = 0;
	gfud->len = 0;
	gfud->data_len = 0;

	g_free(gfud->website.user);
	g_free(gfud->website.passwd);
	g_free(gfud->website.address);
	g_free(gfud->website.page);
	purple_url_parse(new_url, &gfud->website.address, &gfud->website.port,
				   &gfud->website.page, &gfud->website.user, &gfud->website.passwd);

	if (purple_strcasestr(new_url, "https://") != NULL) {
		gfud->is_ssl = TRUE;
		gfud->ssl_connection = purple_ssl_connect(gfud->account,
				gfud->website.address, gfud->website.port,
				ssl_url_fetch_connect_cb, ssl_url_fetch_error_cb, gfud);
	} else {
		gfud->connect_data = purple_proxy_connect(NULL, gfud->account,
				gfud->website.address, gfud->website.port,
				url_fetch_connect_cb, gfud);
	}

	if (gfud->ssl_connection == NULL && gfud->connect_data == NULL)
	{
		purple_util_fetch_url_error(gfud, _("Unable to connect to %s"),
				gfud->website.address);
	}

	return TRUE;
}

/* find the starting point of the content for the specified header and make
 * sure that the content is safe to pass to sscanf */
static const char *
find_header_content(const char *data, gsize data_len, const char *header)
{
	const char *p = NULL;

	gsize header_len = strlen(header);

	if (data_len > header_len) {
		/* Check if the first header matches (data won't start with a \n") */
		if (header[0] == '\n')
			p = (g_ascii_strncasecmp(data, header + 1, header_len - 1) == 0) ? data : NULL;
		if (!p)
			p = purple_strcasestr_len(data, data_len, header, header_len);
		if (p)
			p += header_len;
	}

	/* If we can find the header at all, try to sscanf it.
	 * Response headers should end with at least \r\n, so sscanf is safe,
	 * if we make sure that there is indeed a \n in our header.
	 */
	if (p && g_strstr_len(p, data_len - (p - data), "\n")) {
		return p;
	}

	return NULL;
}

static gsize 
parse_content_len(const char *data, gsize data_len)
{
	gsize content_len = 0;
	const char *p = NULL;

	p = find_header_content(data, data_len, "\nContent-Length: ");
	if (p) {
		sscanf(p, "%" G_GSIZE_FORMAT, &content_len);
		purple_debug_misc("util", "parsed %" G_GSIZE_FORMAT "\n", content_len);
	}

	return content_len;
}

static gboolean
content_is_chunked(const char *data, gsize data_len)
{
	const char *p = find_header_content(data, data_len, "\nTransfer-Encoding: ");
	if (p && g_ascii_strncasecmp(p, "chunked", 7) == 0)
		return TRUE;

	return FALSE;
}

/* Process in-place */
static void
process_chunked_data(char *data, gsize *len)
{
	gsize sz;
	gsize newlen = 0;
	char *p = data;
	char *s = data;

	while (*s) {
		/* Read the size of this chunk */
		if (sscanf(s, "%" G_GSIZE_MODIFIER "x", &sz) != 1)
		{
			purple_debug_error("util", "Error processing chunked data: "
					"Expected data length, found: %s\n", s);
			break;
		}
		if (sz == 0) {
			/* We've reached the last chunk */
			/*
			 * TODO: The spec allows "footers" to follow the last chunk.
			 *       If there is more data after this line then we should
			 *       treat it like a header.
			 */
			break;
		}

		/* Advance to the start of the data */
		s = strstr(s, "\r\n");
		if (s == NULL)
			break;
		s += 2;

		if (sz > MAX_HTTP_CHUNK_SIZE || s + sz > data + *len) {
			purple_debug_error("util", "Error processing chunked data: "
					"Chunk size %" G_GSIZE_FORMAT " bytes was longer "
					"than the data remaining in the buffer (%"
					G_GSIZE_FORMAT " bytes)\n", sz, data + *len - s);
			break;
		}

		/* Move all data overtop of the chunk length that we read in earlier */
		g_memmove(p, s, sz);
		p += sz;
		s += sz;
		newlen += sz;
		if (*s == '\0' || (*s != '\r' && *(s + 1) != '\n')) {
			purple_debug_error("util", "Error processing chunked data: "
					"Expected \\r\\n, found: %s\n", s);
			break;
		}
		s += 2;
	}

	/* NULL terminate the data */
	*p = 0;

	*len = newlen;
}

static void
url_fetch_recv_cb(gpointer url_data, gint source, PurpleInputCondition cond)
{
	PurpleUtilFetchUrlData *gfud = url_data;
	int len;
	char buf[4096];
	char *data_cursor;
	gboolean got_eof = FALSE;

	/*
	 * Read data in a loop until we can't read any more!  This is a
	 * little confusing because we read using a different function
	 * depending on whether the socket is ssl or cleartext.
	 */
	while ((gfud->is_ssl && ((len = purple_ssl_read(gfud->ssl_connection, buf, sizeof(buf))) > 0)) ||
			(!gfud->is_ssl && (len = read(source, buf, sizeof(buf))) > 0))
	{
		if((gfud->len + len) > gfud->max_len) {
			purple_util_fetch_url_error(gfud, _("Error reading from %s: response too long (%d bytes limit)"),
						    gfud->website.address, gfud->max_len);
			return;
		}

		/* If we've filled up our buffer, make it bigger */
		if((gfud->len + len) >= gfud->data_len) {
			while((gfud->len + len) >= gfud->data_len)
				gfud->data_len += sizeof(buf);

			gfud->webdata = g_realloc(gfud->webdata, gfud->data_len);
		}

		data_cursor = gfud->webdata + gfud->len;

		gfud->len += len;

		memcpy(data_cursor, buf, len);

		gfud->webdata[gfud->len] = '\0';

		if(!gfud->got_headers) {
			char *end_of_headers;

			/* See if we've reached the end of the headers yet */
			end_of_headers = strstr(gfud->webdata, "\r\n\r\n");
			if (end_of_headers) {
				guint header_len = (end_of_headers + 4 - gfud->webdata);
				gsize content_len;

				purple_debug_misc("util", "Response headers: '%.*s'\n",
					header_len, gfud->webdata);

				/* See if we can find a redirect. */
				if(parse_redirect(gfud->webdata, header_len, gfud))
					return;

				gfud->got_headers = TRUE;

				/* No redirect. See if we can find a content length. */
				content_len = parse_content_len(gfud->webdata, header_len);
				gfud->chunked = content_is_chunked(gfud->webdata, header_len);

				if (content_len == 0) {
					/* We'll stick with an initial 8192 */
					content_len = 8192;
				} else {
					gfud->has_explicit_data_len = TRUE;
					if (content_len > gfud->max_len) {
						purple_debug_error("util",
								"Overriding explicit Content-Length of %" G_GSIZE_FORMAT " with max of %" G_GSSIZE_FORMAT "\n",
								content_len, gfud->max_len);
						content_len = gfud->max_len;
					}
				}


				/* If we're returning the headers too, we don't need to clean them out */
				if (gfud->include_headers) {
					char *new_data;
					gfud->data_len = content_len + header_len;
					new_data = g_try_realloc(gfud->webdata, gfud->data_len);
					if (new_data == NULL) {
						purple_debug_error("util",
								"Failed to allocate %" G_GSIZE_FORMAT " bytes: %s\n",
								content_len, g_strerror(errno));
						purple_util_fetch_url_error(gfud,
								_("Unable to allocate enough memory to hold "
								  "the contents from %s.  The web server may "
								  "be trying something malicious."),
								gfud->website.address);

						return;
					}
					gfud->webdata = new_data;
				} else {
					char *new_data;
					gsize body_len = gfud->len - header_len;

					content_len = MAX(content_len, body_len);

					new_data = g_try_malloc(content_len);
					if (new_data == NULL) {
						purple_debug_error("util",
								"Failed to allocate %" G_GSIZE_FORMAT " bytes: %s\n",
								content_len, g_strerror(errno));
						purple_util_fetch_url_error(gfud,
								_("Unable to allocate enough memory to hold "
								  "the contents from %s.  The web server may "
								  "be trying something malicious."),
								gfud->website.address);

						return;
					}

					/* We may have read part of the body when reading the headers, don't lose it */
					if (body_len > 0) {
						memcpy(new_data, end_of_headers + 4, body_len);
					}

					/* Out with the old... */
					g_free(gfud->webdata);

					/* In with the new. */
					gfud->len = body_len;
					gfud->data_len = content_len;
					gfud->webdata = new_data;
				}
			}
		}

		if(gfud->has_explicit_data_len && gfud->len >= gfud->data_len) {
			got_eof = TRUE;
			break;
		}
	}

	if(len < 0) {
		if(errno == EAGAIN) {
			return;
		} else {
			purple_util_fetch_url_error(gfud, _("Error reading from %s: %s"),
					gfud->website.address, g_strerror(errno));
			return;
		}
	}

	if((len == 0) || got_eof) {
		gfud->webdata = g_realloc(gfud->webdata, gfud->len + 1);
		gfud->webdata[gfud->len] = '\0';

		if (!gfud->include_headers && gfud->chunked) {
			/* Process only if we don't want the headers. */
			process_chunked_data(gfud->webdata, &gfud->len);
		}

		gfud->callback(gfud, gfud->user_data, gfud->webdata, gfud->len, NULL);
		purple_util_fetch_url_cancel(gfud);
	}
}

static void ssl_url_fetch_recv_cb(gpointer data, PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
	url_fetch_recv_cb(data, -1, cond);
}

/**
 * This function is called when the socket is available to be written
 * to.
 *
 * @param source The file descriptor that can be written to.  This can
 *        be an http connection or it can be the SSL connection of an
 *        https request.  So be careful what you use it for!  If it's
 *        an https request then use purple_ssl_write() instead of
 *        writing to it directly.
 */
static void
url_fetch_send_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleUtilFetchUrlData *gfud;
	int len, total_len;

	gfud = data;

	if (gfud->request == NULL) {

		PurpleProxyInfo *gpi = purple_proxy_get_setup(gfud->account);
		GString *request_str = g_string_new(NULL);

		g_string_append_printf(request_str, "GET %s%s HTTP/%s\r\n"
						    "Connection: close\r\n",
			(gfud->full ? "" : "/"),
			(gfud->full ? (gfud->url ? gfud->url : "") : (gfud->website.page ? gfud->website.page : "")),
			(gfud->http11 ? "1.1" : "1.0"));

		if (gfud->user_agent)
			g_string_append_printf(request_str, "User-Agent: %s\r\n", gfud->user_agent);

		/* Host header is not forbidden in HTTP/1.0 requests, and HTTP/1.1
		 * clients must know how to handle the "chunked" transfer encoding.
		 * Purple doesn't know how to handle "chunked", so should always send
		 * the Host header regardless, to get around some observed problems
		 */
		g_string_append_printf(request_str, "Accept: */*\r\n"
						    "Host: %s\r\n",
			(gfud->website.address ? gfud->website.address : ""));

		if (purple_proxy_info_get_username(gpi) != NULL
				&& (purple_proxy_info_get_type(gpi) == PURPLE_PROXY_USE_ENVVAR
					|| purple_proxy_info_get_type(gpi) == PURPLE_PROXY_HTTP)) {
			/* This chunk of code was copied from proxy.c http_start_connect_tunneling()
			 * This is really a temporary hack - we need a more complete proxy handling solution,
			 * so I didn't think it was worthwhile to refactor for reuse
			 */
			char *t1, *t2, *ntlm_type1;
			char hostname[256];
			int ret;

			ret = gethostname(hostname, sizeof(hostname));
			hostname[sizeof(hostname) - 1] = '\0';
			if (ret < 0 || hostname[0] == '\0') {
				purple_debug_warning("util", "proxy - gethostname() failed -- is your hostname set?");
				strcpy(hostname, "localhost");
			}

			t1 = g_strdup_printf("%s:%s",
				purple_proxy_info_get_username(gpi),
				purple_proxy_info_get_password(gpi) ?
					purple_proxy_info_get_password(gpi) : "");
			t2 = purple_base64_encode((const guchar *)t1, strlen(t1));
			g_free(t1);

			ntlm_type1 = purple_ntlm_gen_type1(hostname, "");

			g_string_append_printf(request_str,
				"Proxy-Authorization: Basic %s\r\n"
				"Proxy-Authorization: NTLM %s\r\n"
				"Proxy-Connection: Keep-Alive\r\n",
				t2, ntlm_type1);
			g_free(ntlm_type1);
			g_free(t2);
		}

		g_string_append(request_str, "\r\n");

		gfud->request = g_string_free(request_str, FALSE);
	}

	if(purple_debug_is_unsafe())
		purple_debug_misc("util", "Request: '%s'\n", gfud->request);
	else
		purple_debug_misc("util", "request constructed\n");

	total_len = strlen(gfud->request);

	if (gfud->is_ssl)
		len = purple_ssl_write(gfud->ssl_connection, gfud->request + gfud->request_written,
				total_len - gfud->request_written);
	else
		len = write(gfud->fd, gfud->request + gfud->request_written,
				total_len - gfud->request_written);

	if (len < 0 && errno == EAGAIN)
		return;
	else if (len < 0) {
		purple_util_fetch_url_error(gfud, _("Error writing to %s: %s"),
				gfud->website.address, g_strerror(errno));
		return;
	}
	gfud->request_written += len;

	if (gfud->request_written < total_len)
		return;

	/* We're done writing our request, now start reading the response */
	if (gfud->is_ssl) {
		purple_input_remove(gfud->inpa);
		gfud->inpa = 0;
		purple_ssl_input_add(gfud->ssl_connection, ssl_url_fetch_recv_cb, gfud);
	} else {
		purple_input_remove(gfud->inpa);
		gfud->inpa = purple_input_add(gfud->fd, PURPLE_INPUT_READ, url_fetch_recv_cb,
			gfud);
	}
}

static void
url_fetch_connect_cb(gpointer url_data, gint source, const gchar *error_message)
{
	PurpleUtilFetchUrlData *gfud;

	gfud = url_data;
	gfud->connect_data = NULL;

	if (source == -1)
	{
		purple_util_fetch_url_error(gfud, _("Unable to connect to %s: %s"),
				(gfud->website.address ? gfud->website.address : ""), error_message);
		return;
	}

	gfud->fd = source;

	gfud->inpa = purple_input_add(source, PURPLE_INPUT_WRITE,
								url_fetch_send_cb, gfud);
	url_fetch_send_cb(gfud, source, PURPLE_INPUT_WRITE);
}

static void ssl_url_fetch_connect_cb(gpointer data, PurpleSslConnection *ssl_connection, PurpleInputCondition cond)
{
	PurpleUtilFetchUrlData *gfud;

	gfud = data;

	gfud->inpa = purple_input_add(ssl_connection->fd, PURPLE_INPUT_WRITE,
			url_fetch_send_cb, gfud);
	url_fetch_send_cb(gfud, ssl_connection->fd, PURPLE_INPUT_WRITE);
}

static void ssl_url_fetch_error_cb(PurpleSslConnection *ssl_connection, PurpleSslErrorType error, gpointer data)
{
	PurpleUtilFetchUrlData *gfud;

	gfud = data;
	gfud->ssl_connection = NULL;

	purple_util_fetch_url_error(gfud, _("Unable to connect to %s: %s"),
			(gfud->website.address ? gfud->website.address : ""),
	purple_ssl_strerror(error));
}

PurpleUtilFetchUrlData *
purple_util_fetch_url_request(const char *url, gboolean full,
		const char *user_agent, gboolean http11,
		const char *request, gboolean include_headers,
		PurpleUtilFetchUrlCallback callback, void *user_data)
{
	return purple_util_fetch_url_request_len_with_account(NULL, url, full,
					     user_agent, http11,
					     request, include_headers, -1,
					     callback, user_data);
}

PurpleUtilFetchUrlData *
purple_util_fetch_url_request_len(const char *url, gboolean full,
		const char *user_agent, gboolean http11,
		const char *request, gboolean include_headers, gssize max_len,
		PurpleUtilFetchUrlCallback callback, void *user_data)
{
	return purple_util_fetch_url_request_len_with_account(NULL, url, full,
			user_agent, http11, request, include_headers, max_len, callback,
			user_data);
}

PurpleUtilFetchUrlData *
purple_util_fetch_url_request_len_with_account(PurpleAccount *account,
		const char *url, gboolean full,	const char *user_agent, gboolean http11,
		const char *request, gboolean include_headers, gssize max_len,
		PurpleUtilFetchUrlCallback callback, void *user_data)
{
	PurpleUtilFetchUrlData *gfud;

	g_return_val_if_fail(url      != NULL, NULL);
	g_return_val_if_fail(callback != NULL, NULL);

	if(purple_debug_is_unsafe())
		purple_debug_info("util",
				 "requested to fetch (%s), full=%d, user_agent=(%s), http11=%d\n",
				 url, full, user_agent?user_agent:"(null)", http11);
	else
		purple_debug_info("util", "requesting to fetch a URL\n");

	gfud = g_new0(PurpleUtilFetchUrlData, 1);

	gfud->callback = callback;
	gfud->user_data  = user_data;
	gfud->url = g_strdup(url);
	gfud->user_agent = g_strdup(user_agent);
	gfud->http11 = http11;
	gfud->full = full;
	gfud->request = g_strdup(request);
	gfud->include_headers = include_headers;
	gfud->fd = -1;
	if (max_len <= 0) {
		max_len = DEFAULT_MAX_HTTP_DOWNLOAD;
		purple_debug_error("util", "Defaulting max download from %s to %" G_GSSIZE_FORMAT "\n", url, max_len);
	}
	gfud->max_len = (gsize) max_len;
	gfud->account = account;

	purple_url_parse(url, &gfud->website.address, &gfud->website.port,
				   &gfud->website.page, &gfud->website.user, &gfud->website.passwd);

	if (purple_strcasestr(url, "https://") != NULL) {
		if (!purple_ssl_is_supported()) {
			purple_util_fetch_url_error(gfud,
					_("Unable to connect to %s: %s"),
					gfud->website.address,
					_("Server requires TLS/SSL, but no TLS/SSL support was found."));
			return NULL;
		}

		gfud->is_ssl = TRUE;
		gfud->ssl_connection = purple_ssl_connect(account,
				gfud->website.address, gfud->website.port,
				ssl_url_fetch_connect_cb, ssl_url_fetch_error_cb, gfud);
	} else {
		gfud->connect_data = purple_proxy_connect(NULL, account,
				gfud->website.address, gfud->website.port,
				url_fetch_connect_cb, gfud);
	}

	if (gfud->ssl_connection == NULL && gfud->connect_data == NULL)
	{
		purple_util_fetch_url_error(gfud, _("Unable to connect to %s"),
				gfud->website.address);
		return NULL;
	}

	return gfud;
}

void
purple_util_fetch_url_cancel(PurpleUtilFetchUrlData *gfud)
{
	if (gfud->ssl_connection != NULL)
		purple_ssl_close(gfud->ssl_connection);

	if (gfud->connect_data != NULL)
		purple_proxy_connect_cancel(gfud->connect_data);

	if (gfud->inpa > 0)
		purple_input_remove(gfud->inpa);

	if (gfud->fd >= 0)
		close(gfud->fd);

	g_free(gfud->website.user);
	g_free(gfud->website.passwd);
	g_free(gfud->website.address);
	g_free(gfud->website.page);
	g_free(gfud->url);
	g_free(gfud->user_agent);
	g_free(gfud->request);
	g_free(gfud->webdata);

	g_free(gfud);
}

const char *
purple_url_decode(const char *str)
{
	static char buf[BUF_LEN];
	guint i, j = 0;
	char *bum;
	char hex[3];

	g_return_val_if_fail(str != NULL, NULL);

	/*
	 * XXX - This check could be removed and buf could be made
	 * dynamically allocated, but this is easier.
	 */
	if (strlen(str) >= BUF_LEN)
		return NULL;

	for (i = 0; i < strlen(str); i++) {

		if (str[i] != '%')
			buf[j++] = str[i];
		else {
			strncpy(hex, str + ++i, 2);
			hex[2] = '\0';

			/* i is pointing to the start of the number */
			i++;

			/*
			 * Now it's at the end and at the start of the for loop
			 * will be at the next character.
			 */
			buf[j++] = strtol(hex, NULL, 16);
		}
	}

	buf[j] = '\0';

	if (!g_utf8_validate(buf, -1, (const char **)&bum))
		*bum = '\0';

	return buf;
}

const char *
purple_url_encode(const char *str)
{
	const char *iter;
	static char buf[BUF_LEN];
	char utf_char[6];
	guint i, j = 0;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(g_utf8_validate(str, -1, NULL), NULL);

	iter = str;
	for (; *iter && j < (BUF_LEN - 1) ; iter = g_utf8_next_char(iter)) {
		gunichar c = g_utf8_get_char(iter);
		/* If the character is an ASCII character and is alphanumeric
		 * no need to escape */
		if (c < 128 && (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~')) {
			buf[j++] = c;
		} else {
			int bytes = g_unichar_to_utf8(c, utf_char);
			for (i = 0; i < bytes; i++) {
				if (j > (BUF_LEN - 4))
					break;
				sprintf(buf + j, "%%%02X", utf_char[i] & 0xff);
				j += 3;
			}
		}
	}

	buf[j] = '\0';

	return buf;
}

/* Originally lifted from
 * http://www.oreillynet.com/pub/a/network/excerpt/spcookbook_chap03/index3.html
 * ... and slightly modified to be a bit more rfc822 compliant
 * ... and modified a bit more to make domain checking rfc1035 compliant
 *     with the exception permitted in rfc1101 for domains to start with digit
 *     but not completely checking to avoid conflicts with IP addresses
 */
gboolean
purple_email_is_valid(const char *address)
{
	const char *c, *domain;
	static char *rfc822_specials = "()<>@,;:\\\"[]";

	g_return_val_if_fail(address != NULL, FALSE);

	if (*address == '.') return FALSE;

	/* first we validate the name portion (name@domain) (rfc822)*/
	for (c = address;  *c;  c++) {
		if (*c == '\"' && (c == address || *(c - 1) == '.' || *(c - 1) == '\"')) {
			while (*++c) {
				if (*c == '\\') {
					if (*c++ && *c < 127 && *c != '\n' && *c != '\r') continue;
					else return FALSE;
				}
				if (*c == '\"') break;
				if (*c < ' ' || *c >= 127) return FALSE;
			}
			if (!*c++) return FALSE;
			if (*c == '@') break;
			if (*c != '.') return FALSE;
			continue;
		}
		if (*c == '@') break;
		if (*c <= ' ' || *c >= 127) return FALSE;
		if (strchr(rfc822_specials, *c)) return FALSE;
	}

	/* It's obviously not an email address if we didn't find an '@' above */
	if (*c == '\0') return FALSE;

	/* strictly we should return false if (*(c - 1) == '.') too, but I think
	 * we should permit user.@domain type addresses - they do work :) */
	if (c == address) return FALSE;

	/* next we validate the domain portion (name@domain) (rfc1035 & rfc1011) */
	if (!*(domain = ++c)) return FALSE;
	do {
		if (*c == '.' && (c == domain || *(c - 1) == '.' || *(c - 1) == '-'))
			return FALSE;
		if (*c == '-' && (*(c - 1) == '.' || *(c - 1) == '@')) return FALSE;
		if ((*c < '0' && *c != '-' && *c != '.') || (*c > '9' && *c < 'A') ||
			(*c > 'Z' && *c < 'a') || (*c > 'z')) return FALSE;
	} while (*++c);

	if (*(c - 1) == '-') return FALSE;

	return ((c - domain) > 3 ? TRUE : FALSE);
}

gboolean
purple_ipv4_address_is_valid(const char *ip)
{
	int c, o1, o2, o3, o4;
	char end;

	g_return_val_if_fail(ip != NULL, FALSE);

	c = sscanf(ip, "%d.%d.%d.%d%c", &o1, &o2, &o3, &o4, &end);
	if (c != 4 || o1 < 0 || o1 > 255 || o2 < 0 || o2 > 255 || o3 < 0 || o3 > 255 || o4 < 0 || o4 > 255)
		return FALSE;
	return TRUE;
}

gboolean
purple_ipv6_address_is_valid(const gchar *ip)
{
	const gchar *c;
	gboolean double_colon = FALSE;
	gint chunks = 1;
	gint in = 0;

	g_return_val_if_fail(ip != NULL, FALSE);

	if (*ip == '\0')
		return FALSE;

	for (c = ip; *c; ++c) {
		if ((*c >= '0' && *c <= '9') ||
		        (*c >= 'a' && *c <= 'f') ||
		        (*c >= 'A' && *c <= 'F')) {
			if (++in > 4)
				/* Only four hex digits per chunk */
				return FALSE;
			continue;
		} else if (*c == ':') {
			/* The start of a new chunk */
			++chunks;
			in = 0;
			if (*(c + 1) == ':') {
				/*
				 * '::' indicates a consecutive series of chunks full
				 * of zeroes. There can be only one of these per address.
				 */
				if (double_colon)
					return FALSE;
				double_colon = TRUE;
			}
		} else
			return FALSE;
	}

	/*
	 * Either we saw a '::' and there were fewer than 8 chunks -or-
	 * we didn't see a '::' and saw exactly 8 chunks.
	 */
	return (double_colon && chunks < 8) || (!double_colon && chunks == 8);
}

/* TODO 3.0.0: Add ipv6 check, too */
gboolean
purple_ip_address_is_valid(const char *ip)
{
	return purple_ipv4_address_is_valid(ip);
}

/* Stolen from gnome_uri_list_extract_uris */
GList *
purple_uri_list_extract_uris(const gchar *uri_list)
{
	const gchar *p, *q;
	gchar *retval;
	GList *result = NULL;

	g_return_val_if_fail (uri_list != NULL, NULL);

	p = uri_list;

	/* We don't actually try to validate the URI according to RFC
	* 2396, or even check for allowed characters - we just ignore
	* comments and trim whitespace off the ends.  We also
	* allow LF delimination as well as the specified CRLF.
	*/
	while (p) {
		if (*p != '#') {
			while (isspace(*p))
				p++;

			q = p;
			while (*q && (*q != '\n') && (*q != '\r'))
				q++;

			if (q > p) {
				q--;
				while (q > p && isspace(*q))
					q--;

				retval = (gchar*)g_malloc (q - p + 2);
				strncpy (retval, p, q - p + 1);
				retval[q - p + 1] = '\0';

				result = g_list_prepend (result, retval);
			}
		}
		p = strchr (p, '\n');
		if (p)
			p++;
	}

	return g_list_reverse (result);
}


/* Stolen from gnome_uri_list_extract_filenames */
GList *
purple_uri_list_extract_filenames(const gchar *uri_list)
{
	GList *tmp_list, *node, *result;

	g_return_val_if_fail (uri_list != NULL, NULL);

	result = purple_uri_list_extract_uris(uri_list);

	tmp_list = result;
	while (tmp_list) {
		gchar *s = (gchar*)tmp_list->data;

		node = tmp_list;
		tmp_list = tmp_list->next;

		if (!strncmp (s, "file:", 5)) {
			node->data = g_filename_from_uri (s, NULL, NULL);
			/* not sure if this fallback is useful at all */
			if (!node->data) node->data = g_strdup (s+5);
		} else {
			result = g_list_delete_link(result, node);
		}
		g_free (s);
	}
	return result;
}

/**************************************************************************
 * UTF8 String Functions
 **************************************************************************/
gchar *
purple_utf8_try_convert(const char *str)
{
	gsize converted;
	gchar *utf8;

	g_return_val_if_fail(str != NULL, NULL);

	if (g_utf8_validate(str, -1, NULL)) {
		return g_strdup(str);
	}

	utf8 = g_locale_to_utf8(str, -1, &converted, NULL, NULL);
	if (utf8 != NULL)
		return utf8;

	utf8 = g_convert(str, -1, "UTF-8", "ISO-8859-15", &converted, NULL, NULL);
	if ((utf8 != NULL) && (converted == strlen(str)))
		return utf8;

	g_free(utf8);

	return NULL;
}

#define utf8_first(x) ((x & 0x80) == 0 || (x & 0xe0) == 0xc0 \
		       || (x & 0xf0) == 0xe0 || (x & 0xf8) == 0xf0)
gchar *
purple_utf8_salvage(const char *str)
{
	GString *workstr;
	const char *end;

	g_return_val_if_fail(str != NULL, NULL);

	workstr = g_string_sized_new(strlen(str));

	do {
		g_utf8_validate(str, -1, &end);
		workstr = g_string_append_len(workstr, str, end - str);
		str = end;
		if (*str == '\0')
			break;
		do {
			workstr = g_string_append_c(workstr, '?');
			str++;
		} while (!utf8_first(*str));
	} while (*str != '\0');

	return g_string_free(workstr, FALSE);
}

gchar *
purple_utf8_strip_unprintables(const gchar *str)
{
	gchar *workstr, *iter;
	const gchar *bad;

	if (str == NULL)
		/* Act like g_strdup */
		return NULL;

	if (!g_utf8_validate(str, -1, &bad)) {
		purple_debug_error("util", "purple_utf8_strip_unprintables(%s) failed; "
		                           "first bad character was %02x (%c)\n",
		                   str, *bad, *bad);
		g_return_val_if_reached(NULL);
	}

	workstr = iter = g_new(gchar, strlen(str) + 1);
	while (*str) {
		gunichar ch = g_utf8_get_char(str);
		gchar *next = g_utf8_next_char(str);
		/*
		 * Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] |
		 *          [#x10000-#x10FFFF]
		 */
		if ((ch == '\t' || ch == '\n' || ch == '\r') ||
				(ch >= 0x20 && ch <= 0xD7FF) ||
				(ch >= 0xE000 && ch <= 0xFFFD) ||
				(ch >= 0x10000 && ch <= 0x10FFFF)) {
			memcpy(iter, str, next - str);
			iter += (next - str);
		}

		str = next;
	}

	/* nul-terminate the new string */
	*iter = '\0';

	return workstr;
}

/*
 * This function is copied from g_strerror() but changed to use
 * gai_strerror().
 */
G_CONST_RETURN gchar *
purple_gai_strerror(gint errnum)
{
	static GStaticPrivate msg_private = G_STATIC_PRIVATE_INIT;
	char *msg;
	int saved_errno = errno;

	const char *msg_locale;

	msg_locale = gai_strerror(errnum);
	if (g_get_charset(NULL))
	{
		/* This string is already UTF-8--great! */
		errno = saved_errno;
		return msg_locale;
	}
	else
	{
		gchar *msg_utf8 = g_locale_to_utf8(msg_locale, -1, NULL, NULL, NULL);
		if (msg_utf8)
		{
			/* Stick in the quark table so that we can return a static result */
			GQuark msg_quark = g_quark_from_string(msg_utf8);
			g_free(msg_utf8);

			msg_utf8 = (gchar *)g_quark_to_string(msg_quark);
			errno = saved_errno;
			return msg_utf8;
		}
	}

	msg = g_static_private_get(&msg_private);
	if (!msg)
	{
		msg = g_new(gchar, 64);
		g_static_private_set(&msg_private, msg, g_free);
	}

	sprintf(msg, "unknown error (%d)", errnum);

	errno = saved_errno;
	return msg;
}

char *
purple_utf8_ncr_encode(const char *str)
{
	GString *out;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(g_utf8_validate(str, -1, NULL), NULL);

	out = g_string_new("");

	for(; *str; str = g_utf8_next_char(str)) {
		gunichar wc = g_utf8_get_char(str);

		/* super simple check. hopefully not too wrong. */
		if(wc >= 0x80) {
			g_string_append_printf(out, "&#%u;", (guint32) wc);
		} else {
			g_string_append_unichar(out, wc);
		}
	}

	return g_string_free(out, FALSE);
}


char *
purple_utf8_ncr_decode(const char *str)
{
	GString *out;
	char *buf, *b;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(g_utf8_validate(str, -1, NULL), NULL);

	buf = (char *) str;
	out = g_string_new("");

	while( (b = strstr(buf, "&#")) ) {
		gunichar wc;
		int base = 0;

		/* append everything leading up to the &# */
		g_string_append_len(out, buf, b-buf);

		b += 2; /* skip past the &# */

		/* strtoul will treat 0x prefix as hex, but not just x */
		if(*b == 'x' || *b == 'X') {
			base = 16;
			b++;
		}

		/* advances buf to the end of the ncr segment */
		wc = (gunichar) strtoul(b, &buf, base);

		/* this mimics the previous impl of ncr_decode */
		if(*buf == ';') {
			g_string_append_unichar(out, wc);
			buf++;
		}
	}

	/* append whatever's left */
	g_string_append(out, buf);

	return g_string_free(out, FALSE);
}


int
purple_utf8_strcasecmp(const char *a, const char *b)
{
	char *a_norm = NULL;
	char *b_norm = NULL;
	int ret = -1;

	if(!a && b)
		return -1;
	else if(!b && a)
		return 1;
	else if(!a && !b)
		return 0;

	if(!g_utf8_validate(a, -1, NULL) || !g_utf8_validate(b, -1, NULL))
	{
		purple_debug_error("purple_utf8_strcasecmp",
						 "One or both parameters are invalid UTF8\n");
		return ret;
	}

	a_norm = g_utf8_casefold(a, -1);
	b_norm = g_utf8_casefold(b, -1);
	ret = g_utf8_collate(a_norm, b_norm);
	g_free(a_norm);
	g_free(b_norm);

	return ret;
}

/* previously conversation::find_nick() */
gboolean
purple_utf8_has_word(const char *haystack, const char *needle)
{
	char *hay, *pin, *p;
	const char *start, *prev_char;
	gunichar before, after;
	int n;
	gboolean ret = FALSE;

	start = hay = g_utf8_strdown(haystack, -1);

	pin = g_utf8_strdown(needle, -1);
	n = strlen(pin);

	while ((p = strstr(start, pin)) != NULL) {
		prev_char = g_utf8_find_prev_char(hay, p);
		before = -2;
		if (prev_char) {
			before = g_utf8_get_char(prev_char);
		}
		after = g_utf8_get_char_validated(p + n, - 1);

		if ((p == hay ||
				/* The character before is a reasonable guess for a word boundary
				   ("!g_unichar_isalnum()" is not a valid way to determine word
				    boundaries, but it is the only reasonable thing to do here),
				   and isn't the '&' from a "&amp;" or some such entity*/
				(before != -2 && !g_unichar_isalnum(before) && *(p - 1) != '&'))
				&& after != -2 && !g_unichar_isalnum(after)) {
			ret = TRUE;
			break;
		}
		start = p + 1;
	}

	g_free(pin);
	g_free(hay);

	return ret;
}

void
purple_print_utf8_to_console(FILE *filestream, char *message)
{
	gchar *message_conv;
	GError *error = NULL;

	/* Try to convert 'message' to user's locale */
	message_conv = g_locale_from_utf8(message, -1, NULL, NULL, &error);
	if (message_conv != NULL) {
		fputs(message_conv, filestream);
		g_free(message_conv);
	}
	else
	{
		/* use 'message' as a fallback */
		g_warning("%s\n", error->message);
		g_error_free(error);
		fputs(message, filestream);
	}
}

gboolean purple_message_meify(char *message, gssize len)
{
	char *c;
	gboolean inside_html = FALSE;

	g_return_val_if_fail(message != NULL, FALSE);

	if(len == -1)
		len = strlen(message);

	for (c = message; *c; c++, len--) {
		if(inside_html) {
			if(*c == '>')
				inside_html = FALSE;
		} else {
			if(*c == '<')
				inside_html = TRUE;
			else
				break;
		}
	}

	if(*c && !g_ascii_strncasecmp(c, "/me ", 4)) {
		memmove(c, c+4, len-3);
		return TRUE;
	}

	return FALSE;
}

char *purple_text_strip_mnemonic(const char *in)
{
	char *out;
	char *a;
	char *a0;
	const char *b;

	g_return_val_if_fail(in != NULL, NULL);

	out = g_malloc(strlen(in)+1);
	a = out;
	b = in;

	a0 = a; /* The last non-space char seen so far, or the first char */

	while(*b) {
		if(*b == '_') {
			if(a > out && b > in && *(b-1) == '(' && *(b+1) && !(*(b+1) & 0x80) && *(b+2) == ')') {
				/* Detected CJK style shortcut (Bug 875311) */
				a = a0;	/* undo the left parenthesis */
				b += 3;	/* and skip the whole mess */
			} else if(*(b+1) == '_') {
				*(a++) = '_';
				b += 2;
				a0 = a;
			} else {
				b++;
			}
		/* We don't want to corrupt the middle of UTF-8 characters */
		} else if (!(*b & 0x80)) {	/* other 1-byte char */
			if (*b != ' ')
				a0 = a;
			*(a++) = *(b++);
		} else {
			/* Multibyte utf8 char, don't look for _ inside these */
			int n = 0;
			int i;
			if ((*b & 0xe0) == 0xc0) {
				n = 2;
			} else if ((*b & 0xf0) == 0xe0) {
				n = 3;
			} else if ((*b & 0xf8) == 0xf0) {
				n = 4;
			} else if ((*b & 0xfc) == 0xf8) {
				n = 5;
			} else if ((*b & 0xfe) == 0xfc) {
				n = 6;
			} else {		/* Illegal utf8 */
				n = 1;
			}
			a0 = a; /* unless we want to delete CJK spaces too */
			for (i = 0; i < n && *b; i += 1) {
				*(a++) = *(b++);
			}
		}
	}
	*a = '\0';

	return out;
}

const char* purple_unescape_filename(const char *escaped) {
	return purple_url_decode(escaped);
}


/* this is almost identical to purple_url_encode (hence purple_url_decode
 * being used above), but we want to keep certain characters unescaped
 * for compat reasons */
const char *
purple_escape_filename(const char *str)
{
	const char *iter;
	static char buf[BUF_LEN];
	char utf_char[6];
	guint i, j = 0;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(g_utf8_validate(str, -1, NULL), NULL);

	iter = str;
	for (; *iter && j < (BUF_LEN - 1) ; iter = g_utf8_next_char(iter)) {
		gunichar c = g_utf8_get_char(iter);
		/* If the character is an ASCII character and is alphanumeric,
		 * or one of the specified values, no need to escape */
		if (c < 128 && (g_ascii_isalnum(c) || c == '@' || c == '-' ||
				c == '_' || c == '.' || c == '#')) {
			buf[j++] = c;
		} else {
			int bytes = g_unichar_to_utf8(c, utf_char);
			for (i = 0; i < bytes; i++) {
				if (j > (BUF_LEN - 4))
					break;
				sprintf(buf + j, "%%%02x", utf_char[i] & 0xff);
				j += 3;
			}
		}
	}
#ifdef _WIN32
	/* File/Directory names in windows cannot end in periods/spaces.
	 * http://msdn.microsoft.com/en-us/library/aa365247%28VS.85%29.aspx
	 */
	while (j > 0 && (buf[j - 1] == '.' || buf[j - 1] == ' '))
		j--;
#endif
	buf[j] = '\0';

	return buf;
}

const char *_purple_oscar_convert(const char *act, const char *protocol)
{
	if (act && purple_strequal(protocol, "prpl-oscar")) {
		int i;
		for (i = 0; act[i] != '\0'; i++)
			if (!isdigit(act[i]))
				return "prpl-aim";
		return "prpl-icq";
	}
	return protocol;
}

void purple_restore_default_signal_handlers(void)
{
#ifndef _WIN32
#ifdef HAVE_SIGNAL_H
	signal(SIGHUP, SIG_DFL);	/* 1: terminal line hangup */
	signal(SIGINT, SIG_DFL);	/* 2: interrupt program */
	signal(SIGQUIT, SIG_DFL);	/* 3: quit program */
	signal(SIGILL,  SIG_DFL);	/* 4:  illegal instruction (not reset when caught) */
	signal(SIGTRAP, SIG_DFL);	/* 5:  trace trap (not reset when caught) */
	signal(SIGABRT, SIG_DFL);	/* 6:  abort program */

#ifdef SIGPOLL
	signal(SIGPOLL,  SIG_DFL);	/* 7:  pollable event (POSIX) */
#endif /* SIGPOLL */

#ifdef SIGEMT
	signal(SIGEMT,  SIG_DFL);	/* 7:  EMT instruction (Non-POSIX) */
#endif /* SIGEMT */

	signal(SIGFPE,  SIG_DFL);	/* 8:  floating point exception */
	signal(SIGBUS,  SIG_DFL);	/* 10: bus error */
	signal(SIGSEGV, SIG_DFL);	/* 11: segmentation violation */
	signal(SIGSYS,  SIG_DFL);	/* 12: bad argument to system call */
	signal(SIGPIPE, SIG_DFL);	/* 13: write on a pipe with no reader */
	signal(SIGALRM, SIG_DFL);	/* 14: real-time timer expired */
	signal(SIGTERM, SIG_DFL);	/* 15: software termination signal */
	signal(SIGCHLD, SIG_DFL);	/* 20: child status has changed */
	signal(SIGXCPU, SIG_DFL);	/* 24: exceeded CPU time limit */
	signal(SIGXFSZ, SIG_DFL);	/* 25: exceeded file size limit */
#endif /* HAVE_SIGNAL_H */
#endif /* !_WIN32 */
}

static void
set_status_with_attrs(PurpleStatus *status, ...)
{
	va_list args;
	va_start(args, status);
	purple_status_set_active_with_attrs(status, TRUE, args);
	va_end(args);
}

void purple_util_set_current_song(const char *title, const char *artist, const char *album)
{
	GList *list = purple_accounts_get_all();
	for (; list; list = list->next) {
		PurplePresence *presence;
		PurpleStatus *tune;
		PurpleAccount *account = list->data;
		if (!purple_account_get_enabled(account, purple_core_get_ui()))
			continue;

		presence = purple_account_get_presence(account);
		tune = purple_presence_get_status(presence, "tune");
		if (!tune)
			continue;
		if (title) {
			set_status_with_attrs(tune,
					PURPLE_TUNE_TITLE, title,
					PURPLE_TUNE_ARTIST, artist,
					PURPLE_TUNE_ALBUM, album,
					NULL);
		} else {
			purple_status_set_active(tune, FALSE);
		}
	}
}

char * purple_util_format_song_info(const char *title, const char *artist, const char *album, gpointer unused)
{
	GString *string;
	char *esc;

	if (!title || !*title)
		return NULL;

	esc = g_markup_escape_text(title, -1);
	string = g_string_new("");
	g_string_append_printf(string, "%s", esc);
	g_free(esc);

	if (artist && *artist) {
		esc = g_markup_escape_text(artist, -1);
		g_string_append_printf(string, _(" - %s"), esc);
		g_free(esc);
	}

	if (album && *album) {
		esc = g_markup_escape_text(album, -1);
		g_string_append_printf(string, _(" (%s)"), esc);
		g_free(esc);
	}

	return g_string_free(string, FALSE);
}

const gchar *
purple_get_host_name(void)
{
	return g_get_host_name();
}

gchar *
purple_uuid_random(void)
{
	guint32 tmp, a, b;

	tmp = g_random_int();
	a = 0x4000 | (tmp & 0xFFF); /* 0x4000 to 0x4FFF */
	tmp >>= 12;
	b = ((1 << 3) << 12) | (tmp & 0x3FFF); /* 0x8000 to 0xBFFF */

	tmp = g_random_int();

	return g_strdup_printf("%08x-%04x-%04x-%04x-%04x%08x",
			g_random_int(),
			tmp & 0xFFFF,
			a,
			b,
			(tmp >> 16) & 0xFFFF, g_random_int());
}
