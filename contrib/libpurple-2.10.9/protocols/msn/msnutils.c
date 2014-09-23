/**
 * @file msnutils.c Utility functions
 *
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
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

#include "msn.h"
#include "msnutils.h"

#include "cipher.h"

/**************************************************************************
 * Util
 **************************************************************************/
char *
rand_guid(void)
{
	return g_strdup_printf("%4X%4X-%4X-%4X-%4X-%4X%4X%4X",
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111);
}

void
msn_parse_format(const char *mime, char **pre_ret, char **post_ret)
{
	char *cur;
	GString *pre  = g_string_new(NULL);
	GString *post = g_string_new(NULL);
	unsigned int colors[3];

	if (pre_ret  != NULL) *pre_ret  = NULL;
	if (post_ret != NULL) *post_ret = NULL;

	cur = strstr(mime, "FN=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		pre = g_string_append(pre, "<FONT FACE=\"");

		while (*cur && *cur != ';')
		{
			pre = g_string_append_c(pre, *cur);
			cur++;
		}

		pre = g_string_append(pre, "\">");
		post = g_string_prepend(post, "</FONT>");
	}

	cur = strstr(mime, "EF=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		while (*cur && *cur != ';')
		{
			pre = g_string_append_c(pre, '<');
			pre = g_string_append_c(pre, *cur);
			pre = g_string_append_c(pre, '>');
			post = g_string_prepend_c(post, '>');
			post = g_string_prepend_c(post, *cur);
			post = g_string_prepend_c(post, '/');
			post = g_string_prepend_c(post, '<');
			cur++;
		}
	}

	cur = strstr(mime, "CO=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		int i;

		i = sscanf(cur, "%02x%02x%02x;", &colors[0], &colors[1], &colors[2]);

		if (i > 0)
		{
			char tag[64];

			if (i == 1)
			{
				colors[1] = 0;
				colors[2] = 0;
			}
			else if (i == 2)
			{
				unsigned int temp = colors[0];

				colors[0] = colors[1];
				colors[1] = temp;
				colors[2] = 0;
			}
			else if (i == 3)
			{
				unsigned int temp = colors[2];

				colors[2] = colors[0];
				colors[0] = temp;
			}

			g_snprintf(tag, sizeof(tag),
					   "<FONT COLOR=\"#%02hhx%02hhx%02hhx\">",
					   colors[0], colors[1], colors[2]);

			pre = g_string_append(pre, tag);
			post = g_string_prepend(post, "</FONT>");
		}
	}

	cur = strstr(mime, "RL=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		if (*cur == '1')
		{
			/* RTL text was received */
			pre = g_string_append(pre, "<SPAN style=\"direction:rtl;text-align:right;\">");
			post = g_string_prepend(post, "</SPAN>");
		}
	}

	cur = g_strdup(purple_url_decode(pre->str));
	g_string_free(pre, TRUE);

	if (pre_ret != NULL)
		*pre_ret = cur;
	else
		g_free(cur);

	cur = g_strdup(purple_url_decode(post->str));
	g_string_free(post, TRUE);

	if (post_ret != NULL)
		*post_ret = cur;
	else
		g_free(cur);
}

/*encode the str to RFC2047 style
 * Currently only support the UTF-8 and base64 encode
 */
char *
msn_encode_mime(const char *str)
{
	gchar *base64, *retval;

	g_return_val_if_fail(str != NULL, NULL);

	base64 = purple_base64_encode((guchar *)str, strlen(str));
	retval = g_strdup_printf("=?utf-8?B?%s?=", base64);
	g_free(base64);

	return retval;
}

/*
 * We need this because we're only supposed to encode spaces in the font
 * names. purple_url_encode() isn't acceptable.
 */
gboolean
msn_encode_spaces(const char *str, char *buf, size_t len)
{
	char *nonspace = buf;

	while (isspace(*str))
		str++;

	for (; *str && len > 1; str++) {
		if (*str == '%') {
			if (len < 4)
				break;
			*buf++ = '%';
			*buf++ = '2';
			*buf++ = '5';
			len -= 3;
			nonspace = buf;
		} else if (*str == ' ') {
			if (len < 4)
				break;
			*buf++ = '%';
			*buf++ = '2';
			*buf++ = '0';
			len -= 3;
		} else {
			*buf++ = *str;
			len--;
			nonspace = buf;
		}
	}

	*nonspace = '\0';

	return (*str == '\0');
}

/*
 * Taken from the zephyr plugin.
 * This parses HTML formatting (put out by one of the gtkimhtml widgets
 * and converts it to msn formatting. It doesn't deal with the tag closing,
 * but gtkimhtml widgets give valid html.
 * It currently deals properly with <b>, <u>, <i>, <font face=...>,
 * <font color=...>, <span dir=...>, <span style="direction: ...">.
 * It ignores <font back=...> and <font size=...>
 */
void
msn_import_html(const char *html, char **attributes, char **message)
{
	int len, retcount = 0;
	const char *c;
	char *msg;
	char *fontface = NULL;
	char fontface_encoded[BUF_LEN];
	char fonteffect[5];
	char fontcolor[7];
	char direction = '0';

	gboolean has_bold = FALSE;
	gboolean has_italic = FALSE;
	gboolean has_underline = FALSE;
	gboolean has_strikethrough = FALSE;

	g_return_if_fail(html       != NULL);
	g_return_if_fail(attributes != NULL);
	g_return_if_fail(message    != NULL);

	len = strlen(html);
	msg = g_malloc0(len + 1);

	memset(fontcolor, 0, sizeof(fontcolor));
	strcat(fontcolor, "0");
	memset(fonteffect, 0, sizeof(fonteffect));

	for (c = html; *c != '\0';)
	{
		if (*c == '<')
		{
			if (!g_ascii_strncasecmp(c + 1, "br>", 3))
			{
				msg[retcount++] = '\r';
				msg[retcount++] = '\n';
				c += 4;
			}
			else if (!g_ascii_strncasecmp(c + 1, "i>", 2))
			{
				if (!has_italic)
				{
					strcat(fonteffect, "I");
					has_italic = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "b>", 2))
			{
				if (!has_bold)
				{
					strcat(fonteffect, "B");
					has_bold = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "u>", 2))
			{
				if (!has_underline)
				{
					strcat(fonteffect, "U");
					has_underline = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "s>", 2))
			{
				if (!has_strikethrough)
				{
					strcat(fonteffect, "S");
					has_strikethrough = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "a href=\"", 8))
			{
				c += 9;

				if (!g_ascii_strncasecmp(c, "mailto:", 7))
					c += 7;

				while ((*c != '\0') && g_ascii_strncasecmp(c, "\">", 2))
					msg[retcount++] = *c++;

				if (*c != '\0')
					c += 2;

				/* ignore descriptive string */
				while ((*c != '\0') && g_ascii_strncasecmp(c, "</a>", 4))
					c++;

				if (*c != '\0')
					c += 4;
			}
			else if (!g_ascii_strncasecmp(c + 1, "span", 4))
			{
				/* Bi-directional text support using CSS properties in span tags */
				c += 5;

				while (*c != '\0' && *c != '>')
				{
					while (*c == ' ')
						c++;
					if (!g_ascii_strncasecmp(c, "dir=\"rtl\"", 9))
					{
						c += 9;
						direction = '1';
					}
					else if (!g_ascii_strncasecmp(c, "style=\"", 7))
					{
						/* Parse inline CSS attributes */
						char *attributes;
						int attr_len = 0;
						c += 7;
						while (*(c + attr_len) != '\0' && *(c + attr_len) != '"')
							attr_len++;
						if (*(c + attr_len) == '"')
						{
							char *attr_dir;
							attributes = g_strndup(c, attr_len);
							attr_dir = purple_markup_get_css_property(attributes, "direction");
							if (attr_dir && (!g_ascii_strncasecmp(attr_dir, "RTL", 3)))
								direction = '1';
							g_free(attr_dir);
							g_free(attributes);
						}

					}
					else
					{
						c++;
					}
				}
				if (*c == '>')
					c++;
			}
			else if (!g_ascii_strncasecmp(c + 1, "font", 4))
			{
				c += 5;

				while ((*c != '\0') && !g_ascii_strncasecmp(c, " ", 1))
					c++;

				if (!g_ascii_strncasecmp(c, "color=\"#", 7))
				{
					c += 8;

					fontcolor[0] = *(c + 4);
					fontcolor[1] = *(c + 5);
					fontcolor[2] = *(c + 2);
					fontcolor[3] = *(c + 3);
					fontcolor[4] = *c;
					fontcolor[5] = *(c + 1);

					c += 8;
				}
				else if (!g_ascii_strncasecmp(c, "face=\"", 6))
				{
					const char *end = NULL;
					const char *comma = NULL;
					unsigned int namelen = 0;

					c += 6;
					end = strchr(c, '\"');
					comma = strchr(c, ',');

					if (comma == NULL || comma > end)
						namelen = (unsigned int)(end - c);
					else
						namelen = (unsigned int)(comma - c);

					fontface = g_strndup(c, namelen);
					c = end + 2;
				}
				else
				{
					/* Drop all unrecognized/misparsed font tags */
					while ((*c != '\0') && g_ascii_strncasecmp(c, "\">", 2))
						c++;

					if (*c != '\0')
						c += 2;
				}
			}
			else
			{
				while ((*c != '\0') && (*c != '>'))
					c++;
				if (*c != '\0')
					c++;
			}
		}
		else if (*c == '&')
		{
			if (!g_ascii_strncasecmp(c, "&lt;", 4))
			{
				msg[retcount++] = '<';
				c += 4;
			}
			else if (!g_ascii_strncasecmp(c, "&gt;", 4))
			{
				msg[retcount++] = '>';
				c += 4;
			}
			else if (!g_ascii_strncasecmp(c, "&nbsp;", 6))
			{
				msg[retcount++] = ' ';
				c += 6;
			}
			else if (!g_ascii_strncasecmp(c, "&quot;", 6))
			{
				msg[retcount++] = '"';
				c += 6;
			}
			else if (!g_ascii_strncasecmp(c, "&amp;", 5))
			{
				msg[retcount++] = '&';
				c += 5;
			}
			else if (!g_ascii_strncasecmp(c, "&apos;", 6))
			{
				msg[retcount++] = '\'';
				c += 6;
			}
			else
				msg[retcount++] = *c++;
		}
		else
			msg[retcount++] = *c++;
	}

	if (fontface == NULL)
		fontface = g_strdup("Segoe UI");

	msn_encode_spaces(fontface, fontface_encoded, BUF_LEN);
	*attributes = g_strdup_printf("FN=%s; EF=%s; CO=%s; PF=0; RL=%c",
								  fontface_encoded,
								  fonteffect, fontcolor, direction);
	*message = msg;

	g_free(fontface);
}

void
msn_parse_socket(const char *str, char **ret_host, int *ret_port)
{
	char *host;
	char *c;
	int port;

	host = g_strdup(str);

	if ((c = strchr(host, ':')) != NULL) {
		*c = '\0';
		port = atoi(c + 1);
	} else {
		port = 1863;
	}

	*ret_host = host;
	*ret_port = port;
}

void
msn_parse_user(const char *str, char **ret_user, int *ret_network)
{
	char **tokens;

	tokens = g_strsplit(str, ":", 2);

	*ret_network = atoi(tokens[0]);
	*ret_user = tokens[1];

	g_free(tokens[0]);
	/* tokens[1] is returned */
	g_free(tokens);
}

gboolean
msn_email_is_valid(const char *passport)
{
	if (purple_email_is_valid(passport)) {
		/* Special characters aren't allowed in domains, so only go to '@' */
		while (*passport != '@') {
			if (*passport == '/')
				return FALSE;
			else if (*passport == '?')
				return FALSE;
			else if (*passport == '=')
				return FALSE;
			/* MSN also doesn't like colons, but that's checked already */

			passport++;
		}

		return TRUE;
	}

	return FALSE;
}

/***************************************************************************
 * MSN Challenge Computing Function
 ***************************************************************************/

/*
 * Handle MSN Challenge computation
 * This algorithm references
 *  http://imfreedom.org/wiki/index.php/MSN:NS/Challenges
 */
#define BUFSIZE	256
void
msn_handle_chl(char *input, char *output)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	const guchar productKey[] = MSNP15_WLM_PRODUCT_KEY;
	const guchar productID[]  = MSNP15_WLM_PRODUCT_ID;
	const char hexChars[]     = "0123456789abcdef";
	char buf[BUFSIZE];
	unsigned char md5Hash[16];
	unsigned char *newHash;
	unsigned int *md5Parts;
	unsigned int *chlStringParts;
	unsigned int newHashParts[5];

	long long nHigh = 0, nLow = 0;

	int len;
	int i;

	/* Create the MD5 hash by using Purple MD5 algorithm */
	cipher = purple_ciphers_find_cipher("md5");
	context = purple_cipher_context_new(cipher, NULL);

	purple_cipher_context_append(context, (guchar *)input, strlen(input));
	purple_cipher_context_append(context, productKey, sizeof(productKey) - 1);
	purple_cipher_context_digest(context, sizeof(md5Hash), md5Hash, NULL);
	purple_cipher_context_destroy(context);

	/* Split it into four integers */
	md5Parts = (unsigned int *)md5Hash;
	for (i = 0; i < 4; i++) {
		/* adjust endianess */
		md5Parts[i] = GUINT_TO_LE(md5Parts[i]);

		/* & each integer with 0x7FFFFFFF          */
		/* and save one unmodified array for later */
		newHashParts[i] = md5Parts[i];
		md5Parts[i] &= 0x7FFFFFFF;
	}

	/* make a new string and pad with '0' to length that's a multiple of 8 */
	snprintf(buf, BUFSIZE - 5, "%s%s", input, productID);
	len = strlen(buf);
	if ((len % 8) != 0) {
		int fix = 8 - (len % 8);
		memset(&buf[len], '0', fix);
		buf[len + fix] = '\0';
		len += fix;
	}

	/* split into integers */
	chlStringParts = (unsigned int *)buf;

	/* this is magic */
	for (i = 0; i < (len / 4); i += 2) {
		long long temp;

		chlStringParts[i] = GUINT_TO_LE(chlStringParts[i]);
		chlStringParts[i + 1] = GUINT_TO_LE(chlStringParts[i + 1]);

		temp = (0x0E79A9C1 * (long long)chlStringParts[i]) % 0x7FFFFFFF;
		temp = (md5Parts[0] * (temp + nLow) + md5Parts[1]) % 0x7FFFFFFF;
		nHigh += temp;

		temp = ((long long)chlStringParts[i + 1] + temp) % 0x7FFFFFFF;
		nLow = (md5Parts[2] * temp + md5Parts[3]) % 0x7FFFFFFF;
		nHigh += nLow;
	}
	nLow = (nLow + md5Parts[1]) % 0x7FFFFFFF;
	nHigh = (nHigh + md5Parts[3]) % 0x7FFFFFFF;

	newHashParts[0] ^= nLow;
	newHashParts[1] ^= nHigh;
	newHashParts[2] ^= nLow;
	newHashParts[3] ^= nHigh;

	/* adjust endianness */
	for(i = 0; i < 4; i++)
		newHashParts[i] = GUINT_TO_LE(newHashParts[i]);

	/* make a string of the parts */
	newHash = (unsigned char *)newHashParts;

	/* convert to hexadecimal */
	for (i = 0; i < 16; i++)
	{
		output[i * 2] = hexChars[(newHash[i] >> 4) & 0xF];
		output[(i * 2) + 1] = hexChars[newHash[i] & 0xF];
	}

	output[32] = '\0';
}

guint8
msn_read8(const char *buf)
{
	return (guint8)buf[0];
}

guint16
msn_read16le(const char *buf)
{
	return GUINT16_FROM_LE(*(guint16 *)buf);
}

guint16
msn_read16be(const char *buf)
{
	return GUINT16_FROM_BE(*(guint16 *)buf);
}

guint32
msn_read32le(const char *buf)
{
	return GUINT32_FROM_LE(*(guint32 *)buf);
}

guint32
msn_read32be(const char *buf)
{
	return GUINT32_FROM_BE(*(guint32 *)buf);
}

guint64
msn_read64le(const char *buf)
{
	return GUINT64_FROM_LE(*(guint64 *)buf);
}

guint64
msn_read64be(const char *buf)
{
	return GUINT64_FROM_BE(*(guint64 *)buf);
}

void
msn_write8(char *buf, guint8 data)
{
	*(guint8 *)buf = data;
}

void
msn_write16le(char *buf, guint16 data)
{
	*(guint16 *)buf = GUINT16_TO_LE(data);
}

void
msn_write16be(char *buf, guint16 data)
{
	*(guint16 *)buf = GUINT16_TO_BE(data);
}

void
msn_write32le(char *buf, guint32 data)
{
	*(guint32 *)buf = GUINT32_TO_LE(data);
}

void
msn_write32be(char *buf, guint32 data)
{
	*(guint32 *)buf = GUINT32_TO_BE(data);
}

void
msn_write64le(char *buf, guint64 data)
{
	*(guint64 *)buf = GUINT64_TO_LE(data);
}

void
msn_write64be(char *buf, guint64 data)
{
	*(guint64 *)buf = GUINT64_TO_BE(data);
}

