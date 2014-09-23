/*
 *					MXit Protocol libPurple Plugin
 *
 *			-- convert between MXit and libPurple markup --
 *
 *				Pieter Loubser	<libpurple@mxit.com>
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

#include	"internal.h"
#include	"debug.h"

#include	"protocol.h"
#include	"mxit.h"
#include	"markup.h"
#include	"chunk.h"
#include	"formcmds.h"
#include	"roster.h"


/* define this to enable emoticon (markup) debugging */
#undef		MXIT_DEBUG_EMO
/* define this to enable markup conversion debugging */
#undef		MXIT_DEBUG_MARKUP


#define		MXIT_FRAME_MAGIC		"MXF\x01"			/* mxit emoticon magic number */
#define		MXIT_MAX_EMO_ID			16					/* maximum emoticon ID length */
#define		COLORCODE_LEN			6					/* colour code ID length */


/* HTML tag types */
#define		MXIT_TAG_COLOR			0x01				/* font color tag */
#define		MXIT_TAG_SIZE			0x02				/* font size tag */
#define		MXIT_MAX_MSG_TAGS		90					/* maximum tags per message (pigdin hack work around) */

/*
 * a HTML tag object
 */
struct tag {
	char	type;
	char*	value;
};


#define		MXIT_VIBE_MSG_COLOR			"#9933FF"
#define		MXIT_FAREWELL_MSG_COLOR		"#949494"


/* vibes */
static const char*	vibes[] = {
	/* 0 */		N_( "Cool Vibrations" ),
	/* 1 */		N_( "Purple Rain" ),
	/* 2 */		N_( "Polite" ),
	/* 3 */		N_( "Rock n Roll" ),
	/* 4 */		N_( "Summer Slumber" ),
	/* 5 */		N_( "Electric Razor" ),
	/* 6 */		N_( "S.O.S" ),
	/* 7 */		N_( "Jack Hammer" ),
	/* 8 */		N_( "Bumble Bee" ),
	/* 9 */		N_( "Ripple" )
};



#ifdef	MXIT_DEBUG_EMO
/*------------------------------------------------------------------------
 * Dump a byte buffer as hexadecimal to the console for debugging purposes.
 *
 *  @param buf				The data to dump
 *  @param len				The length of the data
 */
static void hex_dump( const gchar* buf, int len )
{
	char		msg[256];
	int			pos;
	int			i;

	purple_debug_info( MXIT_PLUGIN_ID, "Dumping data (%i bytes)\n", len );

	memset( msg, 0x00, sizeof( msg ) );
	pos = 0;

	for ( i = 0; i < len; i++ ) {

		if ( pos == 0 )
			pos += sprintf( &msg[pos], "%04i:  ", i );

		pos += sprintf( &msg[pos], "0x%02X ", buf[i] );

		if ( i % 16 == 15 ) {
			pos += sprintf( &msg[pos], "\n" );
			purple_debug_info( MXIT_PLUGIN_ID, "%s", msg );
			pos = 0;
		}
		else if ( i % 16 == 7 )
			pos += sprintf( &msg[pos], " " );
	}

	if ( pos > 0 ) {
		pos += sprintf( &msg[pos], "\n" );
		purple_debug_info( MXIT_PLUGIN_ID, "%s", msg );
		pos = 0;
	}
}
#endif


/*------------------------------------------------------------------------
 * Adds a link to a message
 *
 *  @param mx				The Markup message object
 *	@param replydata		This is the what will be returned when the link gets clicked
 *	@param isStructured		Indicates that the reply is a structured reply
 *	@param displaytext		This is the text for the link which will be displayed in the UI
 */
void mxit_add_html_link( struct RXMsgData* mx, const char* replydata, gboolean isStructured, const char* displaytext )
{
#ifdef	MXIT_LINK_CLICK
	gchar*	link	= NULL;
	gchar*	link64	= NULL;

	/*
	 * The link content is encoded as follows:
	 *  MXIT_LINK_KEY | ACCOUNT_USER | ACCOUNT_PROTO | REPLY_TO | REPLY_FORMAT | REPLY_DATA
	 */
	link = g_strdup_printf( "%s|%s|%s|%s|%i|%s",
			MXIT_LINK_KEY,
			purple_account_get_username( mx->session->acc ),
			purple_account_get_protocol_id( mx->session->acc ),
			mx->from,
			isStructured ? 1 : 0,
			replydata );
	link64 = purple_base64_encode( (const unsigned char*) link, strlen( link ) );

	g_string_append_printf( mx->msg, "<a href=\"%s%s\">%s</a>", MXIT_LINK_PREFIX, link64, displaytext );

	g_free( link64 );
	g_free( link );
#else
	g_string_append_printf( mx->msg, "<b>%s</b>", replydata );
#endif
}


/*------------------------------------------------------------------------
 * Extract an ASN.1 formatted length field from the data.
 *
 *  @param data				The source data
 *  @param size				The extracted length
 *  @return					The number of bytes extracted
 */
static unsigned int asn_getlength( const gchar* data, int* size )
{
	unsigned int	len		= 0;
	unsigned char	bytes;
	unsigned char	byte;
	int				i;

	/* first byte specifies the number of bytes in the length */
	bytes = ( data[0] & ~0x80 );
	if ( bytes > sizeof( unsigned int ) ) {
		/* file too big! */
		return -1;
	}
	data++;

	/* parse out the actual length */
	for ( i = 0; i < bytes; i++ ) {
		byte = data[i];
		len <<= 8;
		len += byte;
	}

	*size = len;
	return bytes + 1;
}


/*------------------------------------------------------------------------
 * Extract an ASN.1 formatted UTF-8 string field from the data.
 *
 *  @param data				The source data
 *  @param type				Expected type of string
 *  @param utf8				The extracted string.  Must be deallocated by caller.
 *  @return					The number of bytes extracted
 */
static int asn_getUtf8( const gchar* data, gchar type, char** utf8 )
{
	unsigned int len;
	gchar *out_str;

	/* validate the field type [1 byte] */
	if ( data[0] != type ) {
		/* this is not a utf-8 string! */
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid UTF-8 encoded string in ASN data (got 0x%02X, expected 0x%02X)\n", data[0], type );
		return -1;
	}

	len = (uint8_t)data[1]; /* length field [1 byte] */
	out_str = g_malloc(len + 1);
	memcpy(out_str, &data[2], len); /* data field */
	out_str[len] = '\0';

	*utf8 = out_str;

	return ( len + 2 );
}


/*------------------------------------------------------------------------
 * Free data associated with a Markup message object.
 *
 *  @param mx				The Markup message object
 */
static void free_markupdata( struct RXMsgData* mx )
{
	if ( mx ) {
		if ( mx->msg )
			g_string_free( mx->msg, TRUE );
		if ( mx->from )
			g_free( mx->from );
		g_free( mx );
	}
}


/*------------------------------------------------------------------------
 * Split the message into smaller messages and send them one at a time
 * to pidgin to be displayed on the UI
 *
 *  @param mx				The received message object
 */
static void mxit_show_split_message( struct RXMsgData* mx )
{
	GString*		msg		= NULL;
	char*			ch		= NULL;
	unsigned int	pos		= 0;
	unsigned int	start	= 0;
	unsigned int	l_nl	= 0;
	unsigned int	l_sp	= 0;
	unsigned int	l_gt	= 0;
	unsigned int	stop	= 0;
	int				tags	= 0;
	gboolean		intag	= FALSE;

	/*
	 * awful hack to work around the awful hack in pidgin to work around GtkIMHtml's
	 * inefficient rendering of messages with lots of formatting changes.
	 * (reference: see the function pidgin_conv_write_conv() in gtkconv.c) the issue
	 * is that when you have more than 100 '<' characters in the message passed to
	 * pidgin, none of the markup (including links) are rendered and thus just dump
	 * all the text as is to the conversation window. this message dump is very
	 * confusing and makes it totally unusable. to work around this we will count
	 * the amount of tags and if its more than the pidgin threshold, we will just
	 * break the message up into smaller parts and send them separately to pidgin.
	 * to the user it will look like multiple messages, but at least he will be able
	 * to use and understand it.
	 */

	ch = mx->msg->str;
	pos = start;
	while ( ch[pos] ) {

		if ( ch[pos] == '<' ) {
			tags++;
			intag = TRUE;
		}
		else if ( ch[pos] == '\n' ) {
			l_nl = pos;
		}
		else if ( ch[pos] == '>' ) {
			l_gt = pos;
			intag = FALSE;
		}
		else if ( ch[pos] == ' ' ) {
			/* ignore spaces inside tags */
			if ( !intag )
				l_sp = pos;
		}
		else if ( ( ch[pos] == 'w' ) && ( pos + 4 < mx->msg->len ) && ( memcmp( &ch[pos], "www.", 4 ) == 0 ) ) {
			tags += 2;
		}
		else if ( ( ch[pos] == 'h' ) && ( pos + 8 < mx->msg->len ) && ( memcmp( &ch[pos], "http://", 7 ) == 0 ) ) {
			tags += 2;
		}

		if ( tags > MXIT_MAX_MSG_TAGS ) {
			/* we have reached the maximum amount of tags pidgin (gtk) can handle per message.
			   so its time to send what we have and then start building a new message */

			/* now find the right place to break the message */
			if ( l_nl > start ) {
				/* break at last '\n' char */
				stop = l_nl;
				ch[stop] = '\0';
				msg = g_string_new( &ch[start] );
				ch[stop] = '\n';
			}
			else if ( l_sp > start ) {
				/* break at last ' ' char */
				stop = l_sp;
				ch[stop] = '\0';
				msg = g_string_new( &ch[start] );
				ch[stop] = ' ';
			}
			else {
				/* break at the last '>' char */
				char t;
				stop = l_gt + 1;
				t = ch[stop];
				ch[stop] = '\0';
				msg = g_string_new( &ch[start] );
				ch[stop] = t;
				stop--;
			}

			/* push message to pidgin */
			serv_got_im( mx->session->con, mx->from, msg->str, mx->flags, mx->timestamp );
			g_string_free( msg, TRUE );
			msg = NULL;

			/* next part need this flag set */
			mx->flags |= PURPLE_MESSAGE_RAW;

			tags = 0;
			start = stop + 1;
			pos = start;
		}
		else
			pos++;
	}

	if ( start != pos ) {
		/* send the last part of the message */

		/* build the string */
		ch[pos] = '\0';
		msg = g_string_new( &ch[start] );
		ch[pos] = '\n';

		/* push message to pidgin */
		serv_got_im( mx->session->con, mx->from, msg->str, mx->flags, mx->timestamp );
		g_string_free( msg, TRUE );
		msg = NULL;
	}
}


/*------------------------------------------------------------------------
 * Insert custom emoticons and inline images into the message (if there
 * are any), then give the message to the UI to display to the user.
 *
 *  @param mx				The received message object
 */
void mxit_show_message( struct RXMsgData* mx )
{
	char*				pos;
	int					start;
	unsigned int		end;
	int					emo_ofs;
	char*				ii;
	char				tag[64];
	int*				img_id;

	if ( mx->got_img ) {
		/* search and replace all emoticon tags with proper image tags */

		while ( ( pos = strstr( mx->msg->str, MXIT_II_TAG ) ) != NULL ) {
			start = pos - mx->msg->str;					/* offset at which MXIT_II_TAG starts */
			emo_ofs = start + strlen( MXIT_II_TAG );	/* offset at which EMO's ID starts */
			end = emo_ofs + 1;							/* offset at which MXIT_II_TAG ends */

			while ( ( end < mx->msg->len ) && ( mx->msg->str[end] != '>' ) )
				end++;

			if ( end == mx->msg->len )			/* end of emoticon tag not found */
				break;

			ii = g_strndup( &mx->msg->str[emo_ofs], end - emo_ofs );

			/* remove inline image tag */
			g_string_erase( mx->msg, start, ( end - start ) + 1 );

			/* find the image entry */
			img_id = (int*) g_hash_table_lookup( mx->session->iimages, ii );
			if ( !img_id ) {
				/* inline image not found, so we will just skip it */
				purple_debug_error( MXIT_PLUGIN_ID, "inline image NOT found (%s)\n", ii );
			}
			else {
				/* insert img tag */
				g_snprintf( tag, sizeof( tag ), "<img id=\"%i\">", *img_id );
				g_string_insert( mx->msg, start, tag );
			}

			g_free( ii );
		}
	}

#ifdef MXIT_DEBUG_MARKUP
	purple_debug_info( MXIT_PLUGIN_ID, "Markup RX (converted): '%s'\n", mx->msg->str );
#endif

	if ( mx->processed ) {
		/* this message has already been taken care of, so just ignore it here */
	}
	else if ( mx->chatid < 0 ) {
		/* normal chat message */
		mxit_show_split_message( mx );
	}
	else {
		/* this is a multimx message */
		serv_got_chat_in( mx->session->con, mx->chatid, mx->from, mx->flags, mx->msg->str, mx->timestamp);
	}

	/* freeup resource */
	free_markupdata( mx );
}


/*------------------------------------------------------------------------
 * Extract the custom emoticon ID from the message.
 *
 *  @param message			The input data
 *  @param emid				The extracted emoticon ID
 */
static void parse_emoticon_str( const char* message, char* emid )
{
	int		i;

	for ( i = 0; ( message[i] != '\0' && message[i] != '}' && i < MXIT_MAX_EMO_ID ); i++ ) {
		emid[i] = message[i];
	}

	if ( message[i] == '\0' ) {
		/* end of message reached, ignore the tag */
		emid[0] = '\0';
	}
	else if ( i == MXIT_MAX_EMO_ID ) {
		/* invalid tag length, ignore the tag */
		emid[0] = '\0';
	}
	else
		emid[i] = '\0';
}


/*------------------------------------------------------------------------
 * Callback function invoked when a custom emoticon request to the WAP site completes.
 *
 *  @param url_data
 *  @param user_data		The Markup message object
 *  @param url_text			The data returned from the WAP site
 *  @param len				The length of the data returned
 *  @param error_message	Descriptive error message
 */
static void emoticon_returned( PurpleUtilFetchUrlData* url_data, gpointer user_data, const gchar* url_text, gsize len, const gchar* error_message )
{
	struct RXMsgData*	mx			= (struct RXMsgData*) user_data;
	const gchar*		data		= url_text;
	unsigned int		pos			= 0;
	int					id;
	char*				str;
	int					em_size		= 0;
	char*				em_data		= NULL;
	char*				em_id		= NULL;
	int*				intptr		= NULL;
	int					res;

	purple_debug_info( MXIT_PLUGIN_ID, "emoticon_returned\n" );

	/* remove request from the async outstanding calls list */
	mx->session->async_calls = g_slist_remove( mx->session->async_calls, url_data );

	if ( !url_text ) {
		/* no reply from the WAP site */
		purple_debug_error( MXIT_PLUGIN_ID, "Error contacting the MXit WAP site. Please try again later (emoticon).\n" );
		goto done;
	}

#ifdef	MXIT_DEBUG_EMO
	hex_dump( data, len );
#endif

	/* validate that the returned data starts with the magic constant that indicates it is a custom emoticon */
	if ( memcmp( MXIT_FRAME_MAGIC, &data[pos], strlen( MXIT_FRAME_MAGIC ) ) != 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid emoticon received from wapsite (bad magic)\n" );
		goto done;
	}
	pos += strlen( MXIT_FRAME_MAGIC );

	/* validate the image frame desc byte */
	if ( data[pos] != '\x6F' ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid emoticon received from wapsite (bad frame desc)\n" );
		goto done;
	}
	pos++;

	/* get the frame image data length */
	res = asn_getlength( &data[pos], &em_size );
	if ( res <= 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid emoticon received from wapsite (bad frame length)\n" );
		goto done;
	}
	pos += res;
#ifdef	MXIT_DEBUG_EMO
	purple_debug_info( MXIT_PLUGIN_ID, "read the length '%i'\n", em_size );
#endif

	/* utf-8 (emoticon name) */
	res = asn_getUtf8( &data[pos], 0x0C, &str );
	if ( res <= 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid emoticon received from wapsite (bad name string)\n" );
		goto done;
	}
	pos += res;
#ifdef	MXIT_DEBUG_EMO
	purple_debug_info( MXIT_PLUGIN_ID, "read the string '%s'\n", str );
#endif
	g_free( str );
	str = NULL;

	/* utf-8 (emoticon shortcut) */
	res = asn_getUtf8( &data[pos], 0x81, &str );
	if ( res <= 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid emoticon received from wapsite (bad shortcut string)\n" );
		goto done;
	}
	pos += res;
#ifdef	MXIT_DEBUG_EMO
	purple_debug_info( MXIT_PLUGIN_ID, "read the string '%s'\n", str );
#endif
	em_id = str;

	/* validate the image data type */
	if ( data[pos] != '\x82' ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid emoticon received from wapsite (bad data type)\n" );
		g_free( em_id );
		goto done;
	}
	pos++;

	/* get the data length */
	res = asn_getlength( &data[pos], &em_size );
	if ( res <= 0 ) {
		/* bad frame length */
		purple_debug_error( MXIT_PLUGIN_ID, "Invalid emoticon received from wapsite (bad data length)\n" );
		g_free( em_id );
		goto done;
	}
	pos += res;
#ifdef	MXIT_DEBUG_EMO
	purple_debug_info( MXIT_PLUGIN_ID, "read the length '%i'\n", em_size );
#endif

	/* strip the mxit markup tags from the emoticon id (eg, .{XY} -> XY) */
	if ( ( em_id[0] == '.' ) && ( em_id[1] == '{' ) ) {
		char	emo[MXIT_MAX_EMO_ID + 1];

		parse_emoticon_str( &em_id[2], emo );
		strcpy( em_id, emo );
	}

	if ( g_hash_table_lookup( mx->session->iimages, em_id ) ) {
		/* emoticon found in the table, so ignore this one */
		g_free( em_id );
		goto done;
	}

	/* make a copy of the data */
	em_data = g_malloc( em_size );
	memcpy( em_data, &data[pos], em_size );

	/* we now have the emoticon, store it in the imagestore */
	id = purple_imgstore_add_with_id( em_data, em_size, NULL );

	/* map the mxit emoticon id to purple image id */
	intptr = g_malloc( sizeof( int ) );
	*intptr = id;
	g_hash_table_insert( mx->session->iimages, em_id, intptr );

	mx->flags |= PURPLE_MESSAGE_IMAGES;
done:
	mx->img_count--;
	if ( ( mx->img_count == 0 ) && ( mx->converted ) ) {
		/*
		 * this was the last outstanding emoticon for this message,
		 * so we can now display it to the user.
		 */
		mxit_show_message( mx );
	}
}


/*------------------------------------------------------------------------
 * Send a request to the MXit WAP site to download the specified emoticon.
 *
 *  @param mx				The Markup message object
 *  @param id				The ID for the emoticon
 */
static void emoticon_request( struct RXMsgData* mx, const char* id )
{
	PurpleUtilFetchUrlData*	url_data;
	const char*				wapserver;
	char*					url;

	purple_debug_info( MXIT_PLUGIN_ID, "sending request for emoticon '%s'\n", id );

	wapserver = purple_account_get_string( mx->session->acc, MXIT_CONFIG_WAPSERVER, DEFAULT_WAPSITE );

	/* reference: "libpurple/util.h" */
	url = g_strdup_printf( "%s/res/?type=emo&mlh=%i&sc=%s&ts=%li", wapserver, MXIT_EMOTICON_SIZE, id, time( NULL ) );
	url_data = purple_util_fetch_url_request( url, TRUE, NULL, TRUE, NULL, FALSE, emoticon_returned, mx );
	if ( url_data )
		mx->session->async_calls = g_slist_prepend( mx->session->async_calls, url_data );

	g_free( url );
}


/*------------------------------------------------------------------------
 * Parse a Vibe command.
 *
 *  @param mx				The Markup message object
 *  @param message			The message text (which contains the vibe)
 *  @return id				The length of the message to skip
 */
static int mxit_parse_vibe( struct RXMsgData* mx, const char* message )
{
	unsigned int	vibeid;

	vibeid = message[2] - '0';

	purple_debug_info( MXIT_PLUGIN_ID, "Vibe received (%i)\n", vibeid );

	if ( vibeid > ( ARRAY_SIZE( vibes ) - 1 ) ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "Unsupported vibe received (%i)\n", vibeid );
		/* unsupported vibe */
		return 0;
	}

	g_string_append_printf( mx->msg, "<font color=\"%s\"><i>%s Vibe...</i></font>", MXIT_VIBE_MSG_COLOR, _( vibes[vibeid] ) );
	return 2;
}


/*------------------------------------------------------------------------
 * Extract the nickname from a chatroom message and display it nicely in
 * libPurple-style (HTML) markup.
 *
 *  @param mx				The received message data object
 *  @param message			The message text
 *  @return					The length of the message to skip
 */
static int mxit_extract_chatroom_nick( struct RXMsgData* mx, char* message, int len, int msgflags )
{
	int		i;

	if ( message[0] == '<' ) {
		/*
		 * The message MIGHT contains an embedded nickname.  But we can't
		 * be sure unless we find the end-of-nickname sequence: (>\n)
		 * Search for it....
		 */
		gboolean	found	= FALSE;

		for ( i = 1; i < len; i++ ) {
			if ( ( message[i] == '\n' ) && ( message[i-1] == '>' ) ) {
				found = TRUE;
				message[i-1] = '\0';	/* loose the '>' */
				i++;					/* and skip the new-line */
				break;
			}
		}

		if ( found ) {
			gchar*		nickname;

			/*
			 * The message definitely had an embedded nickname - generate a marked-up
			 * message to be displayed.
			 */
			nickname = g_markup_escape_text( &message[1], -1 );

			/* Remove any MXit escaping from nickname ("\X" --> "X") */
			if ( msgflags & CP_MSG_MARKUP ) {
				int	nicklen = strlen( nickname );
				int	j, k;

				for ( j = 0, k = 0; j < nicklen; j++ ) {
					if ( nickname[j] == '\\' )
						j++;

					nickname[k] = nickname[j];
					k++;
				}

				nickname[k] = '\0';		/* terminate string */
			}

			/* add nickname within some BOLD markup to the new converted message */
			g_string_append_printf( mx->msg, "<b>%s:</b> ", nickname );

			/* free up the resources */
			g_free( nickname );

			return i;
		}
	}

	return 0;
}



/*------------------------------------------------------------------------
 * Convert a message containing MXit protocol markup to libPurple-style (HTML) markup.
 *
 *  @param mx				The received message data object
 *  @param message			The message text
 *  @param len				The length of the message
 */
void mxit_parse_markup( struct RXMsgData* mx, char* message, int len, short msgtype, int msgflags )
{
	char		tmpstr1[128];
	char*		ch;
	int			i			= 0;

	/* tags */
	gboolean	tag_bold	= FALSE;
	gboolean	tag_under	= FALSE;
	gboolean	tag_italic	= FALSE;
	int			font_size	= 0;

#ifdef MXIT_DEBUG_MARKUP
	purple_debug_info( MXIT_PLUGIN_ID, "Markup RX (original): '%s'\n", message );
#endif


	/*
	 * supported MXit markup:
	 * '*'			bold
	 * '_'			underline
	 * '/'			italics
	 * '$'			highlight text
	 * '.+' 		inc font size
	 * '.-'			dec font size
	 * '#XXXXXX'	foreground color
	 * '.{XX}'		custom emoticon
	 * '\'			escape the following character
	 * '::'			MXit commands
	 */


	if ( is_mxit_chatroom_contact( mx->session, mx->from ) ) {
		/* chatroom message, so we need to extract and skip the sender's nickname
		 * which is embedded inside the message */
		i = mxit_extract_chatroom_nick( mx, message, len, msgflags );
	}

	/* run through the message and check for custom emoticons and markup */
	for ( ; i < len; i++ ) {
		switch ( message[i] ) {


			/* mxit markup parsing */
			case '*' :
					if ( !( msgflags & CP_MSG_MARKUP ) ) {
						g_string_append_c( mx->msg, message[i] );
						break;
					}

					/* bold markup */
					if ( !tag_bold )
						g_string_append( mx->msg, "<b>" );
					else
						g_string_append( mx->msg, "</b>" );
					tag_bold = !tag_bold;
					break;
			case '_' :
					if ( !( msgflags & CP_MSG_MARKUP ) ) {
						g_string_append_c( mx->msg, message[i] );
						break;
					}

					/* underscore markup */
					if ( !tag_under )
						g_string_append( mx->msg, "<u>" );
					else
						g_string_append( mx->msg, "</u>" );
					tag_under = !tag_under;
					break;
			case '/' :
					if ( !( msgflags & CP_MSG_MARKUP ) ) {
						g_string_append_c( mx->msg, message[i] );
						break;
					}

					/* italics markup */
					if ( !tag_italic )
						g_string_append( mx->msg, "<i>" );
					else
						g_string_append( mx->msg, "</i>" );
					tag_italic = !tag_italic;
					break;
			case '$' :
					if ( !( msgflags & CP_MSG_MARKUP ) ) {
						g_string_append_c( mx->msg, message[i] );
						break;
					}
					else if ( i + 1 >= len ) {
						/* message too short for complete link */
						g_string_append_c( mx->msg, '$' );
						break;
					}

					/* find the end tag */
					ch = strstr( &message[i + 1], "$" );
					if ( ch ) {
						/* end found */
						*ch = '\0';
						mxit_add_html_link( mx, &message[i + 1], FALSE, &message[i + 1] );
						*ch = '$';
						i += ( ch - &message[i + 1] ) + 1;
					}
					else {
						g_string_append_c( mx->msg, message[i] );
					}
					/* highlight text */
					break;
			case '#' :
					if ( !( msgflags & CP_MSG_MARKUP ) ) {
						g_string_append_c( mx->msg, message[i] );
						break;
					}
					else if ( i + COLORCODE_LEN >= len ) {
						/* message too short for complete colour code */
						g_string_append_c( mx->msg, '#' );
						break;
					}

					/* foreground (text) color */
					memcpy( tmpstr1, &message[i + 1], COLORCODE_LEN );
					tmpstr1[ COLORCODE_LEN ] = '\0';			/* terminate string */
					if ( strcmp( tmpstr1, "??????" ) == 0 ) {
						/* need to reset the font */
						g_string_append( mx->msg, "</font>" );
						i += COLORCODE_LEN;
					}
					else if ( strspn( tmpstr1, "0123456789abcdefABCDEF") == COLORCODE_LEN ) {
						/* definitely a numeric colour code */
						g_string_append_printf( mx->msg, "<font color=\"#%s\">", tmpstr1 );
						i += COLORCODE_LEN;
					}
					else {
						/* not valid colour markup */
						g_string_append_c( mx->msg, '#' );
					}
					break;
			case '.' :
					if ( i + 1 >= len ) {
						/* message too short */
						g_string_append_c( mx->msg, '.' );
						break;
					}

					if ( ( msgflags & CP_MSG_EMOTICON ) && ( message[i+1] == '{' ) ) {
						/* custom emoticon */
						if ( i + 2 >= len ) {
							/* message too short */
							g_string_append_c( mx->msg, '.' );
							break;
						}

						parse_emoticon_str( &message[i+2], tmpstr1 );
						if ( tmpstr1[0] != '\0' ) {
							mx->got_img = TRUE;

							if ( g_hash_table_lookup( mx->session->iimages, tmpstr1 ) ) {
								/* emoticon found in the cache, so we do not have to request it from the WAPsite */
							}
							else {
								/* request emoticon from the WAPsite */
								mx->img_count++;
								emoticon_request( mx, tmpstr1 );
							}

							g_string_append_printf( mx->msg, MXIT_II_TAG"%s>", tmpstr1 );
							i += strlen( tmpstr1 ) + 2;
						}
						else
							g_string_append_c( mx->msg, '.' );
					}
					else if ( ( msgflags & CP_MSG_MARKUP ) && ( message[i+1] == '+' ) ) {
						/* increment text size */
						font_size++;
						g_string_append_printf( mx->msg, "<font size=\"%+i\">", font_size );
						i++;
					}
					else if ( ( msgflags & CP_MSG_MARKUP ) && ( message[i+1] == '-' ) ) {
						/* decrement text size */
						font_size--;
						g_string_append_printf( mx->msg, "<font size=\"%+i\">", font_size );
						i++;
					}
					else
						g_string_append_c( mx->msg, '.' );

					break;
			case '\\' :
					if ( i + 1 >= len ) {
						/* message too short for an escaped character */
						g_string_append_c( mx->msg, '\\' );
					}
					else {
						/* ignore the next character, because its been escaped */
						g_string_append_c( mx->msg, message[i + 1] );
						i++;
					}
					break;


			/* command parsing */
			case ':' :
					if ( i + 1 >= len ) {
						/* message too short */
						g_string_append_c( mx->msg, ':' );
						break;
					}

					if ( message[i+1] == '@' ) {
						/* this is a vibe! */
						int		size;

						if ( i + 2 >= len ) {
							/* message too short */
							g_string_append_c( mx->msg, message[i] );
							break;
						}

						size = mxit_parse_vibe( mx, &message[i] );
						if ( size == 0 )
							g_string_append_c( mx->msg, message[i] );
						else
							i += size;
					}
					else if ( msgtype != CP_MSGTYPE_COMMAND ) {
						/* this is not a command message */
						g_string_append_c( mx->msg, message[i] );
					}
					else if ( message[i+1] == ':' ) {
						/* parse out the command */
						int		size;

						size = mxit_parse_command( mx, &message[i] );
						if ( size == 0 )
							g_string_append_c( mx->msg, ':' );
						else
							i += size;
					}
					else {
						g_string_append_c( mx->msg, ':' );
					}
					break;


			/* these aren't MXit markup, but are interpreted by libPurple */
			case '<' :
					g_string_append( mx->msg, "&lt;" );
					break;
			case '>' :
					g_string_append( mx->msg, "&gt;" );
					break;
			case '&' :
					g_string_append( mx->msg, "&amp;" );
					break;
			case '"' :
					g_string_append( mx->msg, "&quot;" );
					break;

			default :
					/* text */
					g_string_append_c( mx->msg, message[i] );
					break;
		}
	}

	if ( msgflags & CP_MSG_FAREWELL ) {
		/* this is a farewell message */
		g_string_prepend( mx->msg, "<font color=\""MXIT_FAREWELL_MSG_COLOR"\"><i>" );
		g_string_append( mx->msg, "</i></font>" );
	}
}


/*------------------------------------------------------------------------
 * Insert an inline image command.
 *
 *  @param mx				The message text as processed so far.
 *  @oaram id				The imgstore ID of the inline image.
 */
static void inline_image_add( GString* mx, int id )
{
	PurpleStoredImage *image;
	gconstpointer img_data;
	gsize img_size;
	gchar* enc;

	image = purple_imgstore_find_by_id( id );
	if ( image == NULL )
		return;

	img_data = purple_imgstore_get_data( image );
	img_size = purple_imgstore_get_size( image );

	enc = purple_base64_encode( img_data, img_size );

	g_string_append( mx, "::op=img|dat=" );
	g_string_append( mx, enc );
	g_string_append_c( mx, ':' );

	g_free( enc );
}


/*------------------------------------------------------------------------
 * Convert libpurple (HTML) markup to MXit protocol markup (for sending to MXit).
 * Any MXit markup codes in the original message also need to be escaped.
 *
 *  @param message			The message text containing libPurple (HTML) markup
 *  @return					The message text containing MXit markup
 */
char* mxit_convert_markup_tx( const char* message, int* msgtype )
{
	GString*			mx;
	struct tag*			tag;
	GList*				entry;
	GList*				tagstack	= NULL;
	char*				reply;
	char				color[8];
	int					len			= strlen ( message );
	int					i;

#ifdef MXIT_DEBUG_MARKUP
	purple_debug_info( MXIT_PLUGIN_ID, "Markup TX (original): '%s'\n", message );
#endif

	/*
	 * libPurple uses the following HTML markup codes:
	 *   Bold:			<b>...</b>
	 *   Italics:		<i>...</i>
	 *   Underline:		<u>...</u>
	 *   Strikethrough:	<s>...</s>					(NO MXIT SUPPORT)
	 *   Font size:		<font size="">...</font>
	 *   Font type:		<font face="">...</font>	(NO MXIT SUPPORT)
	 *   Font colour:	<font color=#">...</font>
	 *   Links:			<a href="">...</a>
	 *   Newline:		<br>
	 *   Inline image:  <IMG ID="">
	 * The following characters are also encoded:
	 *   &amp;  &quot;  &lt;  &gt;
	 */

	/* new message data */
	mx = g_string_sized_new( len );

	/* run through the message and check for HTML markup */
	for ( i = 0; i < len; i++ ) {

		switch ( message[i] ) {
			case '<' :
				if ( purple_str_has_prefix( &message[i], "<b>" ) || purple_str_has_prefix( &message[i], "</b>" ) ) {
					/* bold */
					g_string_append_c( mx, '*' );
				}
				else if ( purple_str_has_prefix( &message[i], "<i>" ) || purple_str_has_prefix( &message[i], "</i>" ) ) {
					/* italics */
					g_string_append_c( mx, '/' );
				}
				else if ( purple_str_has_prefix( &message[i], "<u>" ) || purple_str_has_prefix( &message[i], "</u>" ) ) {
					/* underline */
					g_string_append_c( mx, '_' );
				}
				else if ( purple_str_has_prefix( &message[i], "<br>" ) ) {
					/* newline */
					g_string_append_c( mx, '\n' );
				}
				else if ( purple_str_has_prefix( &message[i], "<font size=" ) ) {
					/* font size */
					int fontsize;

					tag = g_new0( struct tag, 1 );
					tag->type = MXIT_TAG_SIZE;
					tagstack = g_list_prepend( tagstack, tag );
					// TODO: implement size control
					if ( sscanf( &message[i+12], "%i", &fontsize ) ) {
						purple_debug_info( MXIT_PLUGIN_ID, "Font size set to %i\n", fontsize );
					}
				}
				else if ( purple_str_has_prefix( &message[i], "<font color=" ) ) {
					/* font colour */
					tag = g_new0( struct tag, 1 );
					tag->type = MXIT_TAG_COLOR;
					tagstack = g_list_append( tagstack, tag );
					memset( color, 0x00, sizeof( color ) );
					memcpy( color, &message[i + 13], 7 );
					g_string_append( mx, color );
				}
				else if ( purple_str_has_prefix( &message[i], "</font>" ) ) {
					/* end of font tag */
					entry = g_list_last( tagstack );
					if ( entry ) {
						tag = entry->data;
						if ( tag->type == MXIT_TAG_COLOR ) {
							/* font color reset */
							g_string_append( mx, "#??????" );
						}
						else if ( tag->type == MXIT_TAG_SIZE ) {
							/* font size */
							// TODO: implement size control
						}
						tagstack = g_list_remove( tagstack, tag );
						g_free( tag );
					}
				}
				else if ( purple_str_has_prefix( &message[i], "<IMG ID=" ) ) {
					/* inline image */
					int imgid;

					if ( sscanf( &message[i+9], "%i", &imgid ) ) {
						inline_image_add( mx, imgid );
						*msgtype = CP_MSGTYPE_COMMAND;		/* inline image must be sent as a MXit command */
					}
				}

				/* skip to end of tag ('>') */
				for ( i++; ( i < len ) && ( message[i] != '>' ) ; i++ );

				break;

			case '*' :	/* MXit bold */
			case '_' :	/* MXit underline */
			case '/' :	/* MXit italic */
			case '#' :	/* MXit font color */
			case '$' :	/* MXit highlight text */
			case '\\' :	/* MXit escape backslash */
				g_string_append( mx, "\\" );				/* escape character */
				g_string_append_c( mx, message[i] );		/* character to escape */
				break;

			case '.' : /* might be a MXit font size change, or custom emoticon */
				if ( i + 1 < len ) {
					if ( ( message[i+1] == '+' ) || ( message[i+1] == '-' ) )
						g_string_append( mx, "\\." );		/* escape "." */
					else
						g_string_append_c( mx, '.' );
				}
				else
					g_string_append_c( mx, '.' );
				break;

			default:
				g_string_append_c( mx, message[i] );
				break;
		}
	}

	/* unescape HTML entities to their literal characters (reference: "libpurple/utils.h") */
	reply = purple_unescape_html( mx->str );

	g_string_free( mx, TRUE );

#ifdef MXIT_DEBUG_MARKUP
	purple_debug_info( MXIT_PLUGIN_ID, "Markup TX (converted): '%s'\n", reply );
#endif

	return reply;
}


/*------------------------------------------------------------------------
 * Free an emoticon entry.
 *
 *  @param key				MXit emoticon ID
 *  @param value			Imagestore ID for emoticon
 *  @param user_data		NULL (unused)
 *  @return					TRUE
 */
static gboolean emoticon_entry_free( gpointer key, gpointer value, gpointer user_data )
{
	int* imgid = value;

	/* key is a string */
	g_free( key );

	/* value is 'id' in imagestore */
	purple_imgstore_unref_by_id( *imgid );
	g_free( value );

	return TRUE;
}


/*------------------------------------------------------------------------
 * Free all entries in the emoticon cache.
 *
 *  @param session			The MXit session object
 */
void mxit_free_emoticon_cache( struct MXitSession* session )
{
	g_hash_table_foreach_remove( session->iimages, emoticon_entry_free, NULL );
	g_hash_table_destroy ( session->iimages );
}
