/*
 *					MXit Protocol libPurple Plugin
 *
 *					-- MXit Forms & Commands --
 *
 *				Andrew Victor	<libpurple@mxit.com>
 *
 *			(C) Copyright 2009	MXit Lifestyle (Pty) Ltd.
 *				<http://www.mxitlifestyle.com>
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
#include "debug.h"

#include "protocol.h"
#include "mxit.h"
#include "markup.h"
#include "formcmds.h"

#undef MXIT_DEBUG_COMMANDS

/*
 * the MXit Command identifiers
 */
typedef enum
{
	MXIT_CMD_UNKNOWN = 0,		/* Unknown command */
	MXIT_CMD_CLEAR,				/* Clear (clear) */
	MXIT_CMD_SENDSMS,			/* Send SMS (sendsms) */
	MXIT_CMD_REPLY,				/* Reply (reply) */
	MXIT_CMD_PLATREQ,			/* Platform Request (platreq) */
	MXIT_CMD_SELECTCONTACT,		/* Select Contact (selc) */
	MXIT_CMD_IMAGE,				/* Inline image (img) */
	MXIT_CMD_SCREENCONFIG,		/* Chat-screen config (csc) */
	MXIT_CMD_SCREENINFO,		/* Chat-screen info (csi) */
	MXIT_CMD_IMAGESTRIP,		/* Image Strip (is) */
	MXIT_CMD_TABLE				/* Table (tbl) */
} MXitCommandType;

/* Chat-screen behaviours (bhvr) */
#define SCREEN_NO_HEADINGS		0x01
#define SCREEN_FULLSCREEN		0x02
#define SCREEN_AUTOCLEAR		0x04
#define SCREEN_NO_AUDIO			0x08
#define SCREEN_NO_MSGPREFIX		0x10
#define SCREEN_NOTIFY			0x20
#define SCREEN_PROGRESSBAR		0x40


/*
 * object for an inline image request with an URL
 */
struct ii_url_request
{
	struct RXMsgData*	mx;
	char*				url;
};


/*------------------------------------------------------------------------
 * Callback function invoked when an inline image request to a web site completes.
 *
 *  @param url_data
 *  @param user_data		The Markup message object
 *  @param url_text			The data returned from the WAP site
 *  @param len				The length of the data returned
 *  @param error_message	Descriptive error message
 */
static void mxit_cb_ii_returned(PurpleUtilFetchUrlData* url_data, gpointer user_data, const gchar* url_text, gsize len, const gchar* error_message)
{
	struct ii_url_request*	iireq		= (struct ii_url_request*) user_data;
	int*					intptr		= NULL;
	int						id;

#ifdef	MXIT_DEBUG_COMMANDS
	purple_debug_info(MXIT_PLUGIN_ID, "Inline Image returned from %s\n", iireq->url);
#endif

	if (!url_text) {
		/* no reply from the WAP site */
		purple_debug_error(MXIT_PLUGIN_ID, "Error downloading Inline Image from %s.\n", iireq->url);
		goto done;
	}

	/* lets first see if we don't have the inline image already in cache */
	if (g_hash_table_lookup(iireq->mx->session->iimages, iireq->url)) {
		/* inline image found in the cache, so we just ignore this reply */
		goto done;
	}

	/* we now have the inline image, store a copy in the imagestore */
	id = purple_imgstore_add_with_id(g_memdup(url_text, len), len, NULL);

	/* map the inline image id to purple image id */
	intptr = g_malloc(sizeof(int));
	*intptr = id;
	g_hash_table_insert(iireq->mx->session->iimages, iireq->url, intptr);

	iireq->mx->flags |= PURPLE_MESSAGE_IMAGES;

done:
	iireq->mx->img_count--;
	if ((iireq->mx->img_count == 0) && (iireq->mx->converted)) {
		/*
		 * this was the last outstanding emoticon for this message,
		 * so we can now display it to the user.
		 */
		mxit_show_message(iireq->mx);
	}

	g_free(iireq);
}


/*------------------------------------------------------------------------
 * Return the command identifier of this MXit Command.
 *
 *  @param cmd			The MXit command <key,value> map
 *  @return				The MXit command identifier
 */
static MXitCommandType command_type(GHashTable* hash)
{
	char* op;
	char* type;

	op = g_hash_table_lookup(hash, "op");
	if (op) {
		if ( strcmp(op, "cmd") == 0 ) {
			type = g_hash_table_lookup(hash, "type");
			if (type == NULL)								/* no command provided */
				return MXIT_CMD_UNKNOWN;
			else if (strcmp(type, "clear") == 0)			/* clear */
				return MXIT_CMD_CLEAR;
			else if (strcmp(type, "sendsms") == 0)			/* send an SMS */
				return MXIT_CMD_SENDSMS;
			else if (strcmp(type, "reply") == 0)			/* list of options */
				return MXIT_CMD_REPLY;
			else if (strcmp(type, "platreq") == 0)			/* platform request */
				return MXIT_CMD_PLATREQ;
			else if (strcmp(type, "selc") == 0)				/* select contact */
				return MXIT_CMD_SELECTCONTACT;
		}
		else if (strcmp(op, "img") == 0)					/* inline image */
			return MXIT_CMD_IMAGE;
		else if (strcmp(op, "csc") == 0)					/* chat-screen config */
			return MXIT_CMD_SCREENCONFIG;
		else if (strcmp(op, "csi") == 0)					/* chat-screen info */
			return MXIT_CMD_SCREENINFO;
		else if (strcmp(op, "is") == 0)						/* image-strip */
			return MXIT_CMD_IMAGESTRIP;
		else if (strcmp(op, "tbl") == 0)					/* table */
			return MXIT_CMD_TABLE;
	}

	return MXIT_CMD_UNKNOWN;
}


/*------------------------------------------------------------------------
 * Tokenize a MXit Command string into a <key,value> map.
 *
 *  @param cmd			The MXit command string
 *  @return				The <key,value> hash-map, or NULL on error.
 */
static GHashTable* command_tokenize(char* cmd)
{
	GHashTable* hash	= NULL;
	gchar**		parts;
	int			i		= 0;

#ifdef MXIT_DEBUG_COMMANDS
	purple_debug_info(MXIT_PLUGIN_ID, "command: '%s'\n", cmd);
#endif

	/* explode the command into parts */
	parts = g_strsplit(cmd, "|", 0);

	hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	/* now break part into a key & value */
	while (parts[i] != NULL) {
		char* value;

		value = strchr(parts[i], '=');		/* find start of value */
		if (value != NULL) {
			*value = '\0';
			value++;
		}

#ifdef MXIT_DEBUG_COMMANDS
		purple_debug_info(MXIT_PLUGIN_ID, "  key='%s' value='%s'\n", parts[i], value);
#endif

		g_hash_table_insert(hash, g_strdup(parts[i]), g_strdup(value));

		i++;
	}

	g_strfreev(parts);

	return hash;
}


/*------------------------------------------------------------------------
 * Process a Clear MXit command.
 *  [::op=cmd|type=clear|clearmsgscreen=true|auto=true|id=12345:]
 *
 *  @param session		The MXit session object
 *  @param from			The sender of the message.
 *  @param hash			The MXit command <key,value> map
 */
static void command_clear(struct MXitSession* session, const char* from, GHashTable* hash)
{
	PurpleConversation *conv;
	char* clearmsgscreen;

	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, session->acc);
	if (conv == NULL) {
		purple_debug_error(MXIT_PLUGIN_ID, _( "Conversation with '%s' not found\n" ), from);
		return;
	}

	clearmsgscreen = g_hash_table_lookup(hash, "clearmsgscreen");
	if ( (clearmsgscreen) && (strcmp(clearmsgscreen, "true") == 0) ) {
		/* this is a command to clear the chat screen */
		purple_conversation_clear_message_history(conv);
	}
}


/*------------------------------------------------------------------------
 * Process a Reply MXit command.
 *  [::op=cmd|type=reply|replymsg=back|selmsg=b) Back|displaymsg=Processing|id=12345:]
 *  [::op=cmd|nm=rep|type=reply|replymsg=back|selmsg=b) Back|displaymsg=Processing|id=12345:]
 *
 *  @param mx			The received message data object
 *  @param hash			The MXit command <key,value> map
 */
static void command_reply(struct RXMsgData* mx, GHashTable* hash)
{
	char* replymsg;
	char* selmsg;
	char* nm;

	selmsg = g_hash_table_lookup(hash, "selmsg");			/* selection message */
	replymsg = g_hash_table_lookup(hash, "replymsg");		/* reply message */
	nm = g_hash_table_lookup(hash, "nm");					/* name parameter */

	if ((selmsg == NULL) || (replymsg == NULL))
		return;		/* these parameters are required */

	if (nm) {		/* indicates response must be a structured response */
		gchar*	seltext = g_markup_escape_text(purple_url_decode(selmsg), -1);
		gchar*	replycmd = g_strdup_printf("type=reply|nm=%s|res=%s|err=0", nm, purple_url_decode(replymsg));

		mxit_add_html_link( mx, replycmd, TRUE, seltext );

		g_free(seltext);
		g_free(replycmd);
	}
	else {
		gchar*	seltext = g_markup_escape_text(purple_url_decode(selmsg), -1);

		mxit_add_html_link( mx, purple_url_decode(replymsg), FALSE, seltext );

		g_free(seltext);
	}
}


/*------------------------------------------------------------------------
 * Process a PlatformRequest MXit command.
 *  [::op=cmd|type=platreq|selmsg=Upgrade MXit|dest=http%3a//m.mxit.com|id=12345:]
 *
 *  @param hash			The MXit command <key,value> map
 *  @param msg			The message to display (as generated so far)
 */
static void command_platformreq(GHashTable* hash, GString* msg)
{
	gchar*	text	= NULL;
	char*	selmsg;
	char*	dest;

	selmsg = g_hash_table_lookup(hash, "selmsg");			/* find the selection message */
	if (selmsg && (strlen(selmsg) > 0)) {
		text = g_markup_escape_text(purple_url_decode(selmsg), -1);
	}

	dest = g_hash_table_lookup(hash, "dest");				/* find the destination */
	if (dest) {
		g_string_append_printf(msg, "<a href=\"%s\">%s</a>", purple_url_decode(dest), (text) ? text : _( "Download" ));		/* add link to display message */
	}

	if (text)
		g_free(text);
}


/*------------------------------------------------------------------------
 * Process an inline image MXit command.
 *  [::op=img|dat=ASDF23408asdflkj2309flkjsadf%3d%3d|algn=1|w=120|h=12|t=100|replymsg=text:]
 *
 *  @param mx			The received message data object
 *  @param hash			The MXit command <key,value> map
 *  @param msg			The message to display (as generated so far)
 */
static void command_image(struct RXMsgData* mx, GHashTable* hash, GString* msg)
{
	const char*	img;
	const char*	reply;
	guchar*		rawimg;
	gsize		rawimglen;
	int			imgid;

	img = g_hash_table_lookup(hash, "dat");
	if (img) {
		rawimg = purple_base64_decode(img, &rawimglen);
		//purple_util_write_data_to_file_absolute("/tmp/mxitinline.png", (char*) rawimg, rawimglen);
		imgid = purple_imgstore_add_with_id(rawimg, rawimglen, NULL);
		g_string_append_printf(msg, "<img id=\"%i\">", imgid);
		mx->flags |= PURPLE_MESSAGE_IMAGES;
	}
	else {
		img = g_hash_table_lookup(hash, "src");
		if (img) {
			struct ii_url_request*	iireq;

			iireq = g_new0(struct ii_url_request,1);
			iireq->url = g_strdup(purple_url_decode(img));
			iireq->mx = mx;

			g_string_append_printf(msg, "%s%s>", MXIT_II_TAG, iireq->url);
			mx->got_img = TRUE;

			/* lets first see if we don't have the inline image already in cache */
			if (g_hash_table_lookup(mx->session->iimages, iireq->url)) {
				/* inline image found in the cache, so we do not have to request it from the web */
				g_free(iireq);
			}
			else {
				/* send the request for the inline image */
				purple_debug_info(MXIT_PLUGIN_ID, "sending request for inline image '%s'\n", iireq->url);

				/* request the image (reference: "libpurple/util.h") */
				purple_util_fetch_url_request(iireq->url, TRUE, NULL, TRUE, NULL, FALSE, mxit_cb_ii_returned, iireq);
				mx->img_count++;
			}
		}
	}

	/* if this is a clickable image, show a click link */
	reply = g_hash_table_lookup(hash, "replymsg");
	if (reply) {
		g_string_append_printf(msg, "\n");
		mxit_add_html_link(mx, purple_url_decode(reply), FALSE, _( "click here" ));
	}
}


/*------------------------------------------------------------------------
 * Process an Imagestrip MXit command.
 *  [::op=is|nm=status|dat=iVBORw0KGgoAAAA%3d%3d|v=63398792426788|fw=8|fh=8|layer=0:]
 *
 *  @param from			The sender of the message.
 *  @param hash			The MXit command <key,value> map
 */
static void command_imagestrip(struct MXitSession* session, const char* from, GHashTable* hash)
{
	const char* name;
	const char* validator;
	const char* tmp;
	int width, height, layer;

	purple_debug_info(MXIT_PLUGIN_ID, "ImageStrip received from %s\n", from);

	/* image strip name */
	name = g_hash_table_lookup(hash, "nm");

	/* validator */
	validator = g_hash_table_lookup(hash, "v");

	/* image data */
	tmp = g_hash_table_lookup(hash, "dat");
	if (tmp) {
		guchar*		rawimg;
		gsize		rawimglen;
		char*		dir;
		char*		escfrom;
		char*		escname;
		char*		escvalidator;
		char*		filename;

		/* base64 decode the image data */
		rawimg = purple_base64_decode(tmp, &rawimglen);
		if (!rawimg)
			return;

		/* save it to a file */
		dir = g_build_filename(purple_user_dir(), "mxit", "imagestrips", NULL);
		purple_build_dir(dir, S_IRUSR | S_IWUSR | S_IXUSR);		/* ensure directory exists */

		escfrom = g_strdup(purple_escape_filename(from));
		escname = g_strdup(purple_escape_filename(name));
		escvalidator = g_strdup(purple_escape_filename(validator));
		filename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s-%s-%s.png", dir, escfrom, escname, escvalidator);

		purple_util_write_data_to_file_absolute(filename, (char*) rawimg, rawimglen);

		g_free(dir);
		g_free(escfrom);
		g_free(escname);
		g_free(escvalidator);
		g_free(filename);
	}

	tmp = g_hash_table_lookup(hash, "fw");
	width = atoi(tmp);

	tmp = g_hash_table_lookup(hash, "fh");
	height = atoi(tmp);

	tmp = g_hash_table_lookup(hash, "layer");
	layer = atoi(tmp);

	purple_debug_info(MXIT_PLUGIN_ID, "ImageStrip %s from %s: [w=%i h=%i l=%i validator=%s]\n", name, from, width, height, layer, validator);
}


/*------------------------------------------------------------------------
 * Process a Chat-Screen-Info MXit command.
 *  [::op=csi:]
 *
 *  @param session		The MXit session object
 *  @param from			The sender of the message.
 */
static void command_screeninfo(struct MXitSession* session, const char* from)
{
	char* response;

	purple_debug_info(MXIT_PLUGIN_ID, "Chat Screen Info received from %s\n", from);

	// TODO: Determine width, height, colors of chat-screen.

	response = g_strdup_printf("::type=csi|res=bhvr,0;w,%i;h,%i;col,0.ffffffff,29.ff000000:", 300, 400);

	/* send response back to MXit */
    mxit_send_message( session, from, response, FALSE, TRUE );

	g_free(response);
}


/*------------------------------------------------------------------------
 * Process a Chat-Screen-Configure MXit command.
 *  [::op=csc|bhvr=|menu=<menu>|col=<colors>:]
 *  where:
 *   menu ::= <menuitem> { ";" <menuitem> }
 *     menuitem ::= { type "," <text> "," <name> "," <meta> }
 *   colors ::= <color> { ";" <color> }
 *     color ::= <colorid> "," <ARGB hex color>
 *
 *  @param session		The MXit session object
 *  @param from			The sender of the message.
 *  @param hash			The MXit command <key,value> map
 */
static void command_screenconfig(struct MXitSession* session, const char* from, GHashTable* hash)
{
	const char* tmp;

	purple_debug_info(MXIT_PLUGIN_ID, "Chat Screen Configure received from %s\n", from);

	/* Behaviour */
	tmp = g_hash_table_lookup(hash, "bhvr");
	if (tmp) {
		purple_debug_info(MXIT_PLUGIN_ID, "  behaviour = %s\n", tmp);
		// TODO: Re-configure conversation screen.
	}

	/* Menu */
	tmp = g_hash_table_lookup(hash, "menu");
	if (tmp) {
		purple_debug_info(MXIT_PLUGIN_ID, "  menu = %s\n", tmp);
		// TODO: Implement conversation-specific sub-menu.
	}

	/* Colours */
	tmp = g_hash_table_lookup(hash, "col");
	if (tmp) {
		purple_debug_info(MXIT_PLUGIN_ID, "  colours = %s\n", tmp);
		// TODO: Re-configuration conversation colors.
	}
}


/*------------------------------------------------------------------------
 * Process a Table Markup MXit command.
 *
 *  @param mx			The received message data object
 *  @param hash			The MXit command <key,value> map
 */
static void command_table(struct RXMsgData* mx, GHashTable* hash)
{
	const char* tmp;
	const char* name;
	int mode;
	int nr_columns = 0, nr_rows = 0;
	gchar** coldata;
	int i, j;

	/* table name */
	name = g_hash_table_lookup(hash, "nm");

	/* number of columns */
	tmp = g_hash_table_lookup(hash, "col");
	nr_columns = atoi(tmp);

	/* number of rows */
	tmp = g_hash_table_lookup(hash, "row");
	nr_rows = atoi(tmp);

	/* mode */
	tmp = g_hash_table_lookup(hash, "mode");
	mode = atoi(tmp);

	/* table data */
	tmp = g_hash_table_lookup(hash, "d");
	coldata = g_strsplit(tmp, "~", 0);			/* split into entries for each row & column */

	purple_debug_info(MXIT_PLUGIN_ID, "Table %s from %s: [cols=%i rows=%i mode=%i]\n", name, mx->from, nr_columns, nr_rows, mode);

	for (i = 0; i < nr_rows; i++) {
		for (j = 0; j < nr_columns; j++) {
			purple_debug_info(MXIT_PLUGIN_ID, " Row %i Column %i = %s\n", i, j, coldata[i*nr_columns + j]);
		}
	}
}


/*------------------------------------------------------------------------
 * Process a received MXit Command message.
 *
 *  @param mx				The received message data object
 *  @param message			The message text
 *  @return					The length of the command
 */
int mxit_parse_command(struct RXMsgData* mx, char* message)
{
	GHashTable* hash	= NULL;
	char*		start;
	char*		end;

	/* ensure that this is really a command */
	if ( ( message[0] != ':' ) || ( message[1] != ':' ) ) {
		/* this is not a command */
		return 0;
	}

	start = message + 2;
	end = strstr(start, ":");
	if (end) {
		/* end of a command found */
		*end = '\0';		/* terminate command string */

		hash = command_tokenize(start);			/* break into <key,value> pairs */
		if (hash) {
			MXitCommandType type = command_type(hash);

			switch (type) {
				case MXIT_CMD_CLEAR :
					command_clear(mx->session, mx->from, hash);
					break;
				case MXIT_CMD_REPLY :
					command_reply(mx, hash);
					break;
				case MXIT_CMD_PLATREQ :
					command_platformreq(hash, mx->msg);
					break;
				case MXIT_CMD_IMAGE :
					command_image(mx, hash, mx->msg);
					break;
				case MXIT_CMD_SCREENCONFIG :
					command_screenconfig(mx->session, mx->from, hash);
					break;
				case MXIT_CMD_SCREENINFO :
					command_screeninfo(mx->session, mx->from);
					break;
				case MXIT_CMD_IMAGESTRIP :
					command_imagestrip(mx->session, mx->from, hash);
					break;
				case MXIT_CMD_TABLE :
					command_table(mx, hash);
					break;
				default :
					/* command unknown, or not currently supported */
					break;
			}
			g_hash_table_destroy(hash);
		}
		*end = ':';

		return end - message;
	}
	else {
		return 0;
	}
}
