/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

#include "encoding.h"

static gchar *
encoding_multi_convert_to_utf8(const gchar *text, gssize textlen, const gchar *encodings, GError **error, gboolean fallback)
{
	gchar *utf8 = NULL;
	const gchar *begin = encodings;
	const gchar *end = NULL;
	gchar *curr_encoding = NULL; /* allocated buffer for encoding name */
	const gchar *curr_encoding_ro = NULL; /* read-only encoding name */

	if (!encodings) {
		purple_debug_error("oscar", "encodings is NULL");
		return NULL;
	}

	for (;;)
	{
		/* extract next encoding */
		end = strchr(begin, ',');
		if (!end) {
			curr_encoding_ro = begin;
		}	else { /* allocate buffer for encoding */
			curr_encoding = g_strndup(begin, end - begin);
			if (!curr_encoding) {
				purple_debug_error("oscar", "Error allocating memory for encoding");
				break;
			}
			curr_encoding_ro = curr_encoding;
		}

		if (!g_ascii_strcasecmp(curr_encoding_ro, "utf-8") && g_utf8_validate(text, textlen, NULL)) {
			break;
		}

		utf8 = g_convert(text, textlen, "UTF-8", curr_encoding_ro, NULL, NULL, NULL);

		if (!end) /* last occurence. do not free curr_encoding: buffer was'nt allocated */
			break;

		g_free(curr_encoding); /* free allocated buffer for encoding here */

		if (utf8) /* text was successfully converted */
			break;

		begin = end + 1;
	}

	if (!utf8 && fallback)
	{ /* "begin" points to last encoding */
		utf8 = g_convert_with_fallback(text, textlen, "UTF-8", begin, "?", NULL, NULL, error);
	}

	return utf8;
}

static gchar *
encoding_extract(const char *encoding)
{
	char *begin, *end;

	if (encoding == NULL) {
		return NULL;
	}

	if (!g_str_has_prefix(encoding, "text/aolrtf; charset=") &&
		!g_str_has_prefix(encoding, "text/x-aolrtf; charset=") &&
		!g_str_has_prefix(encoding, "text/plain; charset=")) {
		return g_strdup(encoding);
	}

	begin = strchr(encoding, '"');
	end = strrchr(encoding, '"');

	if ((begin == NULL) || (end == NULL) || (begin >= end)) {
		return g_strdup(encoding);
	}

	return g_strndup(begin+1, (end-1) - begin);
}

gchar *
oscar_encoding_to_utf8(const char *encoding, const char *text, int textlen)
{
	gchar *utf8 = NULL;
	const gchar *glib_encoding = NULL;
	gchar *extracted_encoding = encoding_extract(encoding);

	if (extracted_encoding == NULL || *extracted_encoding == '\0') {
		purple_debug_info("oscar", "Empty encoding, assuming UTF-8\n");
	} else if (!g_ascii_strcasecmp(extracted_encoding, "iso-8859-1")) {
		glib_encoding = "iso-8859-1";
	} else if (!g_ascii_strcasecmp(extracted_encoding, "ISO-8859-1-Windows-3.1-Latin-1") || !g_ascii_strcasecmp(extracted_encoding, "us-ascii")) {
		glib_encoding = "Windows-1252";
	} else if (!g_ascii_strcasecmp(extracted_encoding, "unicode-2-0")) {
		glib_encoding = "UTF-16BE";
	} else if (g_ascii_strcasecmp(extracted_encoding, "utf-8")) {
		glib_encoding = extracted_encoding;
	}

	if (glib_encoding != NULL) {
		utf8 = encoding_multi_convert_to_utf8(text, textlen, glib_encoding, NULL, FALSE);
	}

	/*
	 * If utf8 is still NULL then either the encoding is utf-8 or
	 * we have been unable to convert the text to utf-8 from the encoding
	 * that was specified.  So we check if the text is valid utf-8 then
	 * just copy it.
	 */
	if (utf8 == NULL) {
		if (textlen != 0 && *text != '\0' && !g_utf8_validate(text, textlen, NULL))
			utf8 = g_strdup(_("(There was an error receiving this message.  The buddy you are speaking with is probably using a different encoding than expected.  If you know what encoding he is using, you can specify it in the advanced account options for your AIM/ICQ account.)"));
		else
			utf8 = g_strndup(text, textlen);
	}

	g_free(extracted_encoding);
	return utf8;
}

gchar *
oscar_utf8_try_convert(PurpleAccount *account, OscarData *od, const gchar *msg)
{
	const char *charset = NULL;
	char *ret = NULL;

	if (msg == NULL)
		return NULL;

	if (g_utf8_validate(msg, -1, NULL))
		return g_strdup(msg);

	if (od->icq)
		charset = purple_account_get_string(account, "encoding", NULL);

	if(charset && *charset)
		ret = encoding_multi_convert_to_utf8(msg, -1, charset, NULL, FALSE);

	if(!ret)
		ret = purple_utf8_try_convert(msg);

	return ret;
}

static gchar *
oscar_convert_to_utf8(const gchar *data, gsize datalen, const char *charsetstr, gboolean fallback)
{
	gchar *ret = NULL;
	GError *err = NULL;

	if ((charsetstr == NULL) || (*charsetstr == '\0'))
		return NULL;

	if (g_ascii_strcasecmp("UTF-8", charsetstr)) {
		ret = encoding_multi_convert_to_utf8(data, datalen, charsetstr, &err, fallback);
		if (err != NULL) {
			purple_debug_warning("oscar", "Conversion from %s failed: %s.\n",
							   charsetstr, err->message);
			g_error_free(err);
		}
	} else {
		if (g_utf8_validate(data, datalen, NULL))
			ret = g_strndup(data, datalen);
		else
			purple_debug_warning("oscar", "String is not valid UTF-8.\n");
	}

	return ret;
}

gchar *
oscar_decode_im(PurpleAccount *account, const char *sourcebn, guint16 charset, const gchar *data, gsize datalen)
{
	gchar *ret = NULL;
	/* charsetstr1 is always set to what the correct encoding should be. */
	const gchar *charsetstr1, *charsetstr2, *charsetstr3 = NULL;

	if ((datalen == 0) || (data == NULL))
		return NULL;

	if (charset == AIM_CHARSET_UNICODE) {
		charsetstr1 = "UTF-16BE";
		charsetstr2 = "UTF-8";
	} else if (charset == AIM_CHARSET_LATIN_1) {
		if ((sourcebn != NULL) && oscar_util_valid_name_icq(sourcebn))
			charsetstr1 = purple_account_get_string(account, "encoding", OSCAR_DEFAULT_CUSTOM_ENCODING);
		else
			charsetstr1 = "ISO-8859-1";
		charsetstr2 = "UTF-8";
	} else if (charset == AIM_CHARSET_ASCII) {
		/* Should just be "ASCII" */
		charsetstr1 = "ASCII";
		charsetstr2 = purple_account_get_string(account, "encoding", OSCAR_DEFAULT_CUSTOM_ENCODING);
	} else if (charset == 0x000d) {
		/* iChat sending unicode over a Direct IM connection = UTF-8 */
		/* Mobile AIM client on multiple devices (including Blackberry Tour, Nokia 3100, and LG VX6000) = ISO-8859-1 */
		charsetstr1 = "UTF-8";
		charsetstr2 = "ISO-8859-1";
		charsetstr3 = purple_account_get_string(account, "encoding", OSCAR_DEFAULT_CUSTOM_ENCODING);
	} else {
		/* Unknown, hope for valid UTF-8... */
		charsetstr1 = "UTF-8";
		charsetstr2 = purple_account_get_string(account, "encoding", OSCAR_DEFAULT_CUSTOM_ENCODING);
	}

	purple_debug_info("oscar", "Parsing IM, charset=0x%04hx, datalen=%" G_GSIZE_FORMAT ", choice1=%s, choice2=%s, choice3=%s\n",
					  charset, datalen, charsetstr1, charsetstr2, (charsetstr3 ? charsetstr3 : ""));

	ret = oscar_convert_to_utf8(data, datalen, charsetstr1, FALSE);
	if (ret == NULL) {
		if (charsetstr3 != NULL) {
			/* Try charsetstr2 without allowing substitutions, then fall through to charsetstr3 if needed */
			ret = oscar_convert_to_utf8(data, datalen, charsetstr2, FALSE);
			if (ret == NULL)
				ret = oscar_convert_to_utf8(data, datalen, charsetstr3, TRUE);
		} else {
			/* Try charsetstr2, allowing substitutions */
			ret = oscar_convert_to_utf8(data, datalen, charsetstr2, TRUE);
		}
	}
	if (ret == NULL) {
		char *str, *salvage, *tmp;

		str = g_malloc(datalen + 1);
		strncpy(str, data, datalen);
		str[datalen] = '\0';
		salvage = purple_utf8_salvage(str);
		tmp = g_strdup_printf(_("(There was an error receiving this message.  Either you and %s have different encodings selected, or %s has a buggy client.)"),
					  sourcebn, sourcebn);
		ret = g_strdup_printf("%s %s", salvage, tmp);
		g_free(tmp);
		g_free(str);
		g_free(salvage);
	}

	return ret;
}

static guint16
get_simplest_charset(const char *utf8)
{
	while (*utf8)
	{
		if ((unsigned char)(*utf8) > 0x7f) {
			/* not ASCII! */
			return AIM_CHARSET_UNICODE;
		}
		utf8++;
	}
	return AIM_CHARSET_ASCII;
}

gchar *
oscar_encode_im(const gchar *msg, gsize *result_len, guint16 *charset, gchar **charsetstr)
{
	guint16 msg_charset = get_simplest_charset(msg);
	if (charset != NULL) {
		*charset = msg_charset;
	}
	if (charsetstr != NULL) {
		*charsetstr = msg_charset == AIM_CHARSET_ASCII ? "us-ascii" : "unicode-2-0";
	}
	return g_convert(msg, -1, msg_charset == AIM_CHARSET_ASCII ? "ASCII" : "UTF-16BE", "UTF-8", NULL, result_len, NULL);
}
