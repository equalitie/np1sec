/*
 * nmrtf.c
 *
 * Copyright (c) 2004 Novell, Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA	02111-1301	USA
 *
 */

/* This code was adapted from the sample RTF reader found here:
 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnrtfspec/html/rtfspec.asp
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include "nmrtf.h"
#include "debug.h"

/* Internal RTF parser error codes */
#define NMRTF_OK 0                      /* Everything's fine! */
#define NMRTF_STACK_UNDERFLOW    1       /* Unmatched '}' */
#define NMRTF_STACK_OVERFLOW     2       /* Too many '{' -- memory exhausted */
#define NMRTF_UNMATCHED_BRACE    3       /* RTF ended during an open group. */
#define NMRTF_INVALID_HEX        4       /* invalid hex character found in data */
#define NMRTF_BAD_TABLE          5       /* RTF table (sym or prop) invalid */
#define NMRTF_ASSERTION		     6       /* Assertion failure */
#define NMRTF_EOF		         7       /* End of file reached while reading RTF */
#define NMRTF_CONVERT_ERROR		 8		 /* Error converting text  */

#define NMRTF_MAX_DEPTH 256

typedef enum
{
	NMRTF_STATE_NORMAL,
	NMRTF_STATE_SKIP,
	NMRTF_STATE_FONTTABLE,
	NMRTF_STATE_BIN,
	NMRTF_STATE_HEX
} NMRtfState;  /* Rtf State */

/* Property types that we care about */
typedef enum
{
	NMRTF_PROP_FONT_IDX,
	NMRTF_PROP_FONT_CHARSET,
	NMRTF_PROP_MAX
} NMRtfProperty;

typedef enum
{
	NMRTF_SPECIAL_BIN,
	NMRTF_SPECIAL_HEX,
	NMRTF_SPECIAL_UNICODE,
	NMRTF_SPECIAL_SKIP
} NMRtfSpecialKwd;

typedef enum
{
	NMRTF_DEST_FONTTABLE,
	NMRTF_DEST_SKIP
} NMRtfDestinationType;

typedef enum
{
	NMRTF_KWD_CHAR,
	NMRTF_KWD_DEST,
	NMRTF_KWD_PROP,
	NMRTF_KWD_SPEC
} NMRtfKeywordType;

typedef struct _NMRTFCharProp
{
	/* All we care about for now is the font.
	 * bold, italic, underline, etc. should be
	 * added here
	 */
	int font_idx;
	int	font_charset;
} NMRtfCharProp;

typedef struct _NMRtfStateSave
{
    NMRtfCharProp chp;
    NMRtfState rds;
    NMRtfState ris;
} NMRtfStateSave;

typedef struct _NMRtfSymbol
{
    char *keyword;          	/* RTF keyword */
    int  default_val;          	/* default value to use */
    gboolean pass_default;  	/* true to use default value from this table */
    NMRtfKeywordType kwd_type;  /* the type of the keyword */
    int  action;               	/* property type if the keyword represents a property */
                            	/* destination type if the keyword represents a destination */
                            	/* character to print if the keyword represents a character */
} NMRtfSymbol;


typedef struct _NMRtfFont
{
	int number;
	char *name;
	int charset;
} NMRtfFont;

/* RTF Context */
struct _NMRtfContext
{
	NMRtfState rds; 		/* destination state */
	NMRtfState ris; 		/* internal state */
	NMRtfCharProp chp; 		/* current character properties (ie. font, bold, italic, etc.) */
	GSList *font_table;		/* the font table */
	GSList *saved;			/* saved state stack */
	int param;				/* numeric parameter for the current keyword */
	long bytes_to_skip; 	/* number of bytes to skip (after encountering \bin) */
	int depth;				/* how many groups deep are we */
	gboolean skip_unknown;	/* if true, skip any unknown destinations (this is set after encountering '\*') */
	char *input;			/* input string */
	char nextch;			/* next char in input */
	GString *ansi;   		/* Temporary ansi text, will be convert/flushed to the output string */
	GString *output; 		/* The plain text UTF8 string */
};

static int rtf_parse(NMRtfContext *ctx);
static int rtf_push_state(NMRtfContext *ctx);
static int rtf_pop_state(NMRtfContext *ctx);
static NMRtfFont *rtf_get_font(NMRtfContext *ctx, int index);
static int rtf_get_char(NMRtfContext *ctx, guchar *ch);
static int rtf_unget_char(NMRtfContext *ctx, guchar ch);
static int rtf_flush_data(NMRtfContext *ctx);
static int rtf_parse_keyword(NMRtfContext *ctx);
static int rtf_dispatch_control(NMRtfContext *ctx, char *keyword, int param, gboolean param_set);
static int rtf_dispatch_char(NMRtfContext *ctx, guchar ch);
static int rtf_dispatch_unicode_char(NMRtfContext *ctx, gunichar ch);
static int rtf_print_char(NMRtfContext *ctx, guchar ch);
static int rtf_print_unicode_char(NMRtfContext *ctx, gunichar ch);
static int rtf_change_destination(NMRtfContext *ctx, NMRtfDestinationType dest);
static int rtf_dispatch_special(NMRtfContext *ctx, NMRtfSpecialKwd special);
static int rtf_apply_property(NMRtfContext *ctx, NMRtfProperty prop, int val);

/* RTF parser tables */

/* Keyword descriptions */
NMRtfSymbol rtf_symbols[] = {
	/* keyword, default, pass_default, keyword_type, action */
    {"fonttbl",  0,   	FALSE,    	NMRTF_KWD_DEST, NMRTF_DEST_FONTTABLE},
	{"f",		 0,		FALSE,		NMRTF_KWD_PROP, NMRTF_PROP_FONT_IDX},
	{"fcharset",  0,  	FALSE,		NMRTF_KWD_PROP,	NMRTF_PROP_FONT_CHARSET},
    {"par",      0,     FALSE,		NMRTF_KWD_CHAR, 0x0a},
    {"line",      0,    FALSE,     	NMRTF_KWD_CHAR, 0x0a},
    {"\0x0a",    0,     FALSE,     	NMRTF_KWD_CHAR, 0x0a},
    {"\0x0d",    0,     FALSE,     	NMRTF_KWD_CHAR, 0x0a},
    {"tab",      0,     FALSE,     	NMRTF_KWD_CHAR, 0x09},
	{"\r",		0,		FALSE,		NMRTF_KWD_CHAR,	'\r'},
	{"\n",		0,		FALSE,		NMRTF_KWD_CHAR,	'\n'},
    {"ldblquote",0,     FALSE,     	NMRTF_KWD_CHAR, '"'},
    {"rdblquote",0,     FALSE,     	NMRTF_KWD_CHAR, '"'},
    {"{",        0,     FALSE,     	NMRTF_KWD_CHAR, '{'},
    {"}",        0,     FALSE,     	NMRTF_KWD_CHAR, '}'},
    {"\\",       0,     FALSE,     	NMRTF_KWD_CHAR,  '\\'},
    {"bin",      0,     FALSE,     	NMRTF_KWD_SPEC, NMRTF_SPECIAL_BIN},
    {"*",        0,     FALSE,     	NMRTF_KWD_SPEC, NMRTF_SPECIAL_SKIP},
    {"'",        0,     FALSE,     	NMRTF_KWD_SPEC, NMRTF_SPECIAL_HEX},
	{"u",		0,		FALSE,		NMRTF_KWD_SPEC,	NMRTF_SPECIAL_UNICODE},
    {"colortbl", 0,     FALSE,     NMRTF_KWD_DEST,	NMRTF_DEST_SKIP},
    {"author",   0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"buptim",   0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"comment",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"creatim",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"doccomm",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"footer",   0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"footerf",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"footerl",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"footerr",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"footnote", 0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"ftncn",    0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"ftnsep",   0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"ftnsepc",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"header",   0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"headerf",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"headerl",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"headerr",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"info",     0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"keywords", 0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"operator", 0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"pict",     0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"printim",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"private1", 0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"revtim",   0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"rxe",      0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"stylesheet",   0, FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"subject",  0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"tc",       0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"title",    0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"txe",      0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP},
    {"xe",       0,     FALSE,     NMRTF_KWD_DEST,  NMRTF_DEST_SKIP}
};
int table_size = sizeof(rtf_symbols) / sizeof(NMRtfSymbol);

NMRtfContext *
nm_rtf_init()
{
	NMRtfContext *ctx = g_new0(NMRtfContext, 1);
	ctx->nextch = -1;
	ctx->ansi = g_string_new("");
	ctx->output = g_string_new("");
	return ctx;
}

char *
nm_rtf_strip_formatting(NMRtfContext *ctx, const char *input)
{
	int status;

	ctx->input = (char *)input;
	status = rtf_parse(ctx);
	if (status == NMRTF_OK)
		return g_strdup(ctx->output->str);

	purple_debug_info("novell", "RTF parser failed with error code %d\n", status);
	return NULL;
}

void
nm_rtf_deinit(NMRtfContext *ctx)
{
	GSList *node;
	NMRtfFont *font;
	NMRtfStateSave *save;

	if (ctx) {
		for (node = ctx->font_table; node; node = node->next) {
			font = node->data;
			g_free(font->name);
			g_free(font);
			node->data = NULL;
		}
		g_slist_free(ctx->font_table);
		for (node = ctx->saved; node; node = node->next) {
			save = node->data;
			g_free(save);
			node->data = NULL;
		}
		g_slist_free(ctx->saved);
		g_string_free(ctx->ansi, TRUE);
		g_string_free(ctx->output, TRUE);
		g_free(ctx);
	}
}

static const char *
get_current_encoding(NMRtfContext *ctx)
{
	NMRtfFont *font;

	font = rtf_get_font(ctx, ctx->chp.font_idx);

	switch (font->charset) {
		case 0:
			return "CP1252";
		case 77:
			return "MACINTOSH";
		case 78:
			return "SJIS";
		case 128:
			return "CP932";
		case 129:
			return "CP949";
		case 130:
			return "CP1361";
		case 134:
			return "CP936";
		case 136:
			return "CP950";
		case 161:
			return "CP1253";
		case 162:
			return "CP1254";
		case 163:
			return "CP1258";
		case 181:
		case 177:
			return "CP1255";
		case 178:
		case 179:
		case 180:
			return "CP1256";
		case 186:
			return "CP1257";
		case 204:
			return "CP1251";
		case 222:
			return "CP874";
		case 238:
			return "CP1250";
		case 254:
			return "CP437";
		default:
			purple_debug_info("novell", "Unhandled font charset %d\n", font->charset);
			return "CP1252";
	}
}


/*
 * Add an entry to the font table
 */
static int
rtf_add_font_entry(NMRtfContext *ctx, int number, const char *name, int charset)
{
    NMRtfFont *font = g_new0(NMRtfFont, 1);

	font->number = number;
    font->name = g_strdup(name);
	font->charset = charset;

	purple_debug_info("novell", "Adding font to table: #%d\t%s\t%d\n",
					font->number, font->name, font->charset);

	ctx->font_table = g_slist_append(ctx->font_table, font);

    return NMRTF_OK;
}

/*
 * Return the nth entry in the font table
 */
static NMRtfFont *
rtf_get_font(NMRtfContext *ctx, int nth)
{
	NMRtfFont *font;

	font = g_slist_nth_data(ctx->font_table, nth);

	return font;
}

/*
 * Step 1:
 * Isolate RTF keywords and send them to rtf_parse_keyword;
 * Push and pop state at the start and end of RTF groups;
 * Send text to rtf_dispatch_char for further processing.
 */
static int
rtf_parse(NMRtfContext *ctx)
{
    int status;
    guchar ch;
    guchar hex_byte = 0;
    int hex_count = 2;
	int len;

	if (ctx->input == NULL)
		return NMRTF_OK;

    while (rtf_get_char(ctx, &ch) == NMRTF_OK) {
        if (ctx->depth < 0)
            return NMRTF_STACK_UNDERFLOW;

		/* if we're parsing binary data, handle it directly */
        if (ctx->ris == NMRTF_STATE_BIN) {
            if ((status = rtf_dispatch_char(ctx, ch)) != NMRTF_OK)
                return status;
        } else {
            switch (ch) {
				case '{':
					if (ctx->depth > NMRTF_MAX_DEPTH)
						return NMRTF_STACK_OVERFLOW;
                    rtf_flush_data(ctx);
					if ((status = rtf_push_state(ctx)) != NMRTF_OK)
						return status;
					break;
				case '}':
					rtf_flush_data(ctx);

					/* for some reason there is always an unwanted '\par' at the end */
					if (ctx->rds == NMRTF_STATE_NORMAL) {
						len = ctx->output->len;
						if (ctx->output->str[len-1] == '\n')
							ctx->output = g_string_truncate(ctx->output, len-1);
					}

					if ((status = rtf_pop_state(ctx)) != NMRTF_OK)
						return status;

					if (ctx->depth < 0)
						return NMRTF_STACK_OVERFLOW;
					break;
				case '\\':
					if ((status = rtf_parse_keyword(ctx)) != NMRTF_OK)
						return status;
					break;
				case 0x0d:
				case 0x0a:          /*  cr and lf are noise characters... */
					break;
				default:
					if (ctx->ris == NMRTF_STATE_NORMAL) {
						if ((status = rtf_dispatch_char(ctx, ch)) != NMRTF_OK)
							return status;
					} else {               /* parsing a hex encoded character */
						if (ctx->ris != NMRTF_STATE_HEX)
							return NMRTF_ASSERTION;

						hex_byte = hex_byte << 4;
						if (isdigit(ch))
							hex_byte += (char) ch - '0';
						else {
							if (islower(ch)) {
								if (ch < 'a' || ch > 'f')
									return NMRTF_INVALID_HEX;
								hex_byte += (char) ch - 'a' + 10;
							} else {
								if (ch < 'A' || ch > 'F')
									return NMRTF_INVALID_HEX;
								hex_byte += (char) ch - 'A' + 10;
							}
						}
						hex_count--;
						if (hex_count == 0) {
							if ((status = rtf_dispatch_char(ctx, hex_byte)) != NMRTF_OK)
								return status;
							hex_count = 2;
							hex_byte = 0;
							ctx->ris = NMRTF_STATE_NORMAL;
						}
					}
					break;
            }
        }
    }
    if (ctx->depth < 0)
        return NMRTF_STACK_OVERFLOW;
    if (ctx->depth > 0)
        return NMRTF_UNMATCHED_BRACE;
    return NMRTF_OK;
}

/*
 * Push the current state onto stack
 */
static int
rtf_push_state(NMRtfContext *ctx)
{
    NMRtfStateSave *save = g_new0(NMRtfStateSave, 1);
    save->chp = ctx->chp;
    save->rds = ctx->rds;
    save->ris = ctx->ris;
	ctx->saved = g_slist_prepend(ctx->saved, save);
    ctx->ris = NMRTF_STATE_NORMAL;
    (ctx->depth)++;
    return NMRTF_OK;
}

/*
 * Restore the state at the top of the stack
 */
static int
rtf_pop_state(NMRtfContext *ctx)
{
    NMRtfStateSave *save_old;
	GSList *link_old;

    if (ctx->saved == NULL)
        return NMRTF_STACK_UNDERFLOW;

	save_old = ctx->saved->data;
    ctx->chp = save_old->chp;
    ctx->rds = save_old->rds;
    ctx->ris = save_old->ris;
    (ctx->depth)--;

    g_free(save_old);
	link_old = ctx->saved;
	ctx->saved = g_slist_remove_link(ctx->saved, link_old);
	g_slist_free_1(link_old);
    return NMRTF_OK;
}

/*
 * Step 2:
 * Get a control word (and its associated value) and
 * dispatch the control.
 */
static int
rtf_parse_keyword(NMRtfContext *ctx)
{
	int status = NMRTF_OK;
    guchar ch;
    gboolean param_set = FALSE;
    gboolean is_neg = FALSE;
    int param = 0;
    char keyword[30];
    char parameter[20];
	int i;

    keyword[0] = '\0';
    parameter[0] = '\0';
    if ((status = rtf_get_char(ctx, &ch)) != NMRTF_OK)
        return status;

    if (!isalpha(ch)) {
		/* a control symbol; no delimiter. */
        keyword[0] = (char) ch;
        keyword[1] = '\0';
        return rtf_dispatch_control(ctx, keyword, 0, param_set);
    }

	/* parse keyword */
	for (i = 0; isalpha(ch) && (i < sizeof(keyword) - 1); rtf_get_char(ctx, &ch)) {
		keyword[i] = (char) ch;
		i++;
	}
	keyword[i] = '\0';

	/* check for '-' indicated a negative parameter value  */
    if (ch == '-') {
        is_neg = TRUE;
        if ((status = rtf_get_char(ctx, &ch)) != NMRTF_OK)
            return status;
    }

	/* check for numerical param */
    if (isdigit(ch)) {

        param_set = TRUE;
		for (i = 0; isdigit(ch) && (i < sizeof(parameter) - 1); rtf_get_char(ctx, &ch)) {
			parameter[i] = (char) ch;
			i++;
		}
		parameter[i] = '\0';

        ctx->param = param = atoi(parameter);
        if (is_neg)
            ctx->param = param = -param;
    }

	/* space after control is optional, put character back if it is not a space */
    if (ch != ' ')
        rtf_unget_char(ctx, ch);

    return rtf_dispatch_control(ctx, keyword, param, param_set);
}

/*
 * Route the character to the appropriate destination
 */
static int
rtf_dispatch_char(NMRtfContext *ctx, guchar ch)
{
    if (ctx->ris == NMRTF_STATE_BIN && --(ctx->bytes_to_skip) <= 0)
        ctx->ris = NMRTF_STATE_NORMAL;

    switch (ctx->rds) {
		case NMRTF_STATE_SKIP:
			return NMRTF_OK;
		case NMRTF_STATE_NORMAL:
			return rtf_print_char(ctx, ch);
        case NMRTF_STATE_FONTTABLE:
            if (ch == ';')  {
				rtf_add_font_entry(ctx, ctx->chp.font_idx,
								   ctx->ansi->str, ctx->chp.font_charset);
				g_string_truncate(ctx->ansi, 0);
            }
            else {
                return rtf_print_char(ctx, ch);
            }
            return NMRTF_OK;
		default:
			return NMRTF_OK;
    }
}

/* Handle a unicode character */
static int
rtf_dispatch_unicode_char(NMRtfContext *ctx, gunichar ch)
{
    switch (ctx->rds) {
		case NMRTF_STATE_SKIP:
			return NMRTF_OK;
		case NMRTF_STATE_NORMAL:
        case NMRTF_STATE_FONTTABLE:
			return rtf_print_unicode_char(ctx, ch);
		default:
			return NMRTF_OK;
    }
}

/*
 * Output a character
 */
static int
rtf_print_char(NMRtfContext *ctx, guchar ch)
{

	ctx->ansi = g_string_append_c(ctx->ansi, ch);

    return NMRTF_OK;
}

/*
 * Output a unicode character
 */
static int
rtf_print_unicode_char(NMRtfContext *ctx, gunichar ch)
{
	char buf[7];
	int num;

	/* convert and flush the ansi buffer to the utf8 buffer */
	rtf_flush_data(ctx);

	/* convert the unicode character to utf8 and add directly to the output buffer */
	num = g_unichar_to_utf8((gunichar) ch, buf);
	buf[num] = 0;
	purple_debug_info("novell", "converted unichar 0x%X to utf8 char %s\n", ch, buf);

	ctx->output = g_string_append(ctx->output, buf);
	return NMRTF_OK;
}

/*
 * Flush the output text
 */
static int
rtf_flush_data(NMRtfContext *ctx)
{
    int status = NMRTF_OK;
	char *conv_data = NULL;
	const char *enc = NULL;
	GError *gerror = NULL;

    if (ctx->rds == NMRTF_STATE_NORMAL && ctx->ansi->len > 0) {
		enc = get_current_encoding(ctx);
		conv_data = g_convert(ctx->ansi->str, ctx->ansi->len, "UTF-8", enc,
							  NULL, NULL, &gerror);
		if (conv_data) {
			ctx->output = g_string_append(ctx->output, conv_data);
			g_free(conv_data);
			ctx->ansi = g_string_truncate(ctx->ansi, 0);
		} else {
			status = NMRTF_CONVERT_ERROR;
			purple_debug_info("novell", "failed to convert data! error code = %d msg = %s\n",
							gerror->code, gerror->message);
			g_free(gerror);
		}
	}

    return status;
}

/*
 * Handle a property change
 */
static int
rtf_apply_property(NMRtfContext *ctx, NMRtfProperty prop, int val)
{
    if (ctx->rds == NMRTF_STATE_SKIP)  /* If we're skipping text, */
        return NMRTF_OK;          /* don't do anything. */

	/* Need to flush any temporary data before a property change*/
	rtf_flush_data(ctx);

    switch (prop) {
		case NMRTF_PROP_FONT_IDX:
			ctx->chp.font_idx = val;
			break;
		case NMRTF_PROP_FONT_CHARSET:
			ctx->chp.font_charset = val;
			break;
		default:
			return NMRTF_BAD_TABLE;
    }

    return NMRTF_OK;
}

/*
 * Step 3.
 * Search the table for keyword and evaluate it appropriately.
 *
 * Inputs:
 * keyword:   The RTF control to evaluate.
 * param:     The parameter of the RTF control.
 * param_set: TRUE if the control had a parameter; (that is, if param is valid)
 *            FALSE if it did not.
 */
static int
rtf_dispatch_control(NMRtfContext *ctx, char *keyword, int param, gboolean param_set)
{
    int idx;

    for (idx = 0; idx < table_size; idx++) {
        if (strcmp(keyword, rtf_symbols[idx].keyword) == 0)
            break;
	}

    if (idx == table_size)  {
        if (ctx->skip_unknown)
            ctx->rds = NMRTF_STATE_SKIP;
        ctx->skip_unknown = FALSE;
        return NMRTF_OK;
    }

    /* found it! use kwd_type and action to determine what to do with it. */
    ctx->skip_unknown = FALSE;
    switch (rtf_symbols[idx].kwd_type) {
		case NMRTF_KWD_PROP:
			if (rtf_symbols[idx].pass_default || !param_set)
				param = rtf_symbols[idx].default_val;
			return rtf_apply_property(ctx, rtf_symbols[idx].action, param);
		case NMRTF_KWD_CHAR:
			return rtf_dispatch_char(ctx, rtf_symbols[idx].action);
		case NMRTF_KWD_DEST:
			return rtf_change_destination(ctx, rtf_symbols[idx].action);
		case NMRTF_KWD_SPEC:
			return rtf_dispatch_special(ctx, rtf_symbols[idx].action);
		default:
			return NMRTF_BAD_TABLE;
    }
    return NMRTF_BAD_TABLE;
}

/*
 * Change to the destination specified.
 */
static int
rtf_change_destination(NMRtfContext *ctx, NMRtfDestinationType type)
{
	/* if we're skipping text, don't do anything */
    if (ctx->rds == NMRTF_STATE_SKIP)
        return NMRTF_OK;

    switch (type) {
		case NMRTF_DEST_FONTTABLE:
            ctx->rds = NMRTF_STATE_FONTTABLE;
			g_string_truncate(ctx->ansi, 0);
            break;
		default:
			ctx->rds = NMRTF_STATE_SKIP;       /* when in doubt, skip it... */
			break;
    }
    return NMRTF_OK;
}

/*
 * Dispatch an RTF control that needs special processing
 */
static int
rtf_dispatch_special(NMRtfContext *ctx, NMRtfSpecialKwd type)
{
	int status = NMRTF_OK;
	guchar ch;

    if (ctx->rds == NMRTF_STATE_SKIP && type != NMRTF_SPECIAL_BIN)  /* if we're skipping, and it's not */
        return NMRTF_OK;                        /* the \bin keyword, ignore it. */

    switch (type) {
		case NMRTF_SPECIAL_BIN:
			ctx->ris = NMRTF_STATE_BIN;
			ctx->bytes_to_skip = ctx->param;
			break;
		case NMRTF_SPECIAL_SKIP:
			ctx->skip_unknown = TRUE;
			break;
		case NMRTF_SPECIAL_HEX:
			ctx->ris = NMRTF_STATE_HEX;
			break;
		case NMRTF_SPECIAL_UNICODE:
			purple_debug_info("novell", "parsing unichar\n");
			status = rtf_dispatch_unicode_char(ctx, ctx->param);
 			/* Skip next char */
			if (status == NMRTF_OK)
				status = rtf_get_char(ctx, &ch);
			break;
		default:
			status = NMRTF_BAD_TABLE;
			break;
    }

    return status;
}

/*
 * Get the next character from the input stream
 */
static int
rtf_get_char(NMRtfContext *ctx, guchar *ch)
{
    if (ctx->nextch >= 0) {
        *ch = ctx->nextch;
        ctx->nextch = -1;
    }
    else {
		*ch = *(ctx->input);
		ctx->input++;
    }

	if (*ch)
		return NMRTF_OK;
	else
		return NMRTF_EOF;
}

/*
 * Move a character back into the input stream
 */
static int
rtf_unget_char(NMRtfContext *ctx, guchar ch)
{
    ctx->nextch = ch;
    return NMRTF_OK;
}
