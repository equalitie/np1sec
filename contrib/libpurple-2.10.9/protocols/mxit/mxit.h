/*
 *					MXit Protocol libPurple Plugin
 *
 *					--  MXit libPurple plugin API --
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

#ifndef		_MXIT_H_
#define		_MXIT_H_


#include "internal.h"


#if defined( __APPLE__ )
/* apple architecture */
#ifndef HOST_NAME_MAX
#define		HOST_NAME_MAX				512
#endif
#elif defined( _WIN32 )
/* windows architecture */
#ifndef HOST_NAME_MAX
#define		HOST_NAME_MAX				512
#endif
#include	"libc_interface.h"
#elif defined( __linux__ )
/* linux architecture */
#include	<net/if.h>
#include	<sys/ioctl.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#else
/* other architecture */
#ifndef HOST_NAME_MAX
#define		HOST_NAME_MAX				512
#endif
#endif


#include	"protocol.h"
#include	"profile.h"


/* Plugin details */
#define		MXIT_PLUGIN_ID				"prpl-loubserp-mxit"
#define		MXIT_PLUGIN_NAME			"MXit"
#define		MXIT_PLUGIN_EMAIL			"Pieter Loubser <libpurple@mxit.com>"
#define		MXIT_PLUGIN_WWW				"http://www.mxit.com"
#define		MXIT_PLUGIN_SUMMARY			"MXit Protocol Plugin"
#define		MXIT_PLUGIN_DESC			"MXit"

#define		MXIT_HTTP_USERAGENT			"libpurple-"DISPLAY_VERSION


/* default connection settings */
#define		DEFAULT_SERVER				"stream.mxit.co.za"
#define		DEFAULT_PORT				9119
#define		DEFAULT_WAPSITE				"http://www.mxit.com"
#define		DEFAULT_HTTP_SERVER			"http://int.poll.mxit.com:80/mxit"


/* Purple account configuration variable names */
#define		MXIT_CONFIG_STATE			"state"
#define		MXIT_CONFIG_WAPSERVER		"wap_server"
#define		MXIT_CONFIG_DISTCODE		"distcode"
#define		MXIT_CONFIG_CLIENTKEY		"clientkey"
#define		MXIT_CONFIG_DIALCODE		"dialcode"
#define		MXIT_CONFIG_SERVER_ADDR		"server"
#define		MXIT_CONFIG_SERVER_PORT		"port"
#define		MXIT_CONFIG_HTTPSERVER		"httpserver"
#define		MXIT_CONFIG_SPLASHID		"splashid"
#define		MXIT_CONFIG_SPLASHCLICK		"splashclick"
#define		MXIT_CONFIG_SPLASHPOPUP		"splashpopup"
#define		MXIT_CONFIG_COUNTRYCODE		"cc"
#define		MXIT_CONFIG_LOCALE			"locale"
#define		MXIT_CONFIG_USE_HTTP		"use_http"


/* account states */
#define		MXIT_STATE_LOGIN			0x00
#define		MXIT_STATE_REGISTER1		0x01
#define		MXIT_STATE_REGISTER2		0x02


/* Client session flags */
#define		MXIT_FLAG_CONNECTED			0x01		/* established connection to the server */
#define		MXIT_FLAG_LOGGEDIN			0x02		/* user currently logged in */
#define		MXIT_FLAG_FIRSTROSTER		0x04		/* set to true once the first roster update has been received and processed */


/* Maximum number of search results */
#define		MXIT_SEARCHRESULTS_MAX		30


/* define this to enable the link clicking support */
#define		MXIT_LINK_CLICK

#ifdef		MXIT_LINK_CLICK
#define		MXIT_LINK_PREFIX			"gopher://"
#define		MXIT_LINK_KEY				"MXIT"
#endif


#define		ARRAY_SIZE( x )				( sizeof( x ) / sizeof( x[0] ) )


/*
 * data structure containing all MXit session information
 */
struct MXitSession {
	/* socket connection */
	char				server[HOST_NAME_MAX];		/* MXit server name to connect to */
	int					port;						/* MXit server port to connect on */
	int					fd;							/* connection file descriptor */

	/* http connection */
	gboolean			http;						/* connect to MXit via HTTP and not by socket */
	char				http_server[HOST_NAME_MAX];	/* MXit HTTP server */
	unsigned int		http_sesid;					/* HTTP session id */
	unsigned int		http_seqno;					/* HTTP request sequence number */
	guint				http_timer_id;				/* timer resource id (pidgin) */
	int					http_interval;				/* poll inverval */
	gint64				http_last_poll;				/* the last time a poll has been sent */
	guint				http_handler;				/* HTTP connection handler */

	/* other servers */
	char				voip_server[HOST_NAME_MAX];	/* voice/video server */

	/* client */
	struct login_data*	logindata;
	char*				encpwd;						/* encrypted password */
	char				distcode[64];				/* distribution code */
	char				clientkey[16];				/* client key */
	char				dialcode[8];				/* dialing code */
	short				flags;						/* client session flags (see above) */

	/* personal (profile) */
	struct MXitProfile*	profile;					/* user's profile information */
	char*				uid;						/* the user's UID */

	/* libpurple */
	PurpleAccount*		acc;						/* pointer to the libpurple internal account struct */
	PurpleConnection*	con;						/* pointer to the libpurple internal connection struct */

	/* transmit */
	struct tx_queue		queue;						/* transmit packet queue (FIFO mode) */
	gint64				last_tx;					/* timestamp of last packet sent */
	int					outack;						/* outstanding ack packet */
	guint				q_slow_timer_id;			/* timer handle for slow tx queue */
	guint				q_fast_timer_id;			/* timer handle for fast tx queue */
	GSList*				async_calls;				/* list of current outstanding async calls */

	/* receive */
	char				rx_lbuf[16];				/* receive byte buffer (socket packet length) */
	char				rx_dbuf[CP_MAX_PACKET];		/* receive byte buffer (raw data) */
	unsigned int		rx_i;						/* receive buffer current index */
	int					rx_res;						/* amount of bytes still outstanding for the current packet */
	char				rx_state;					/* current receiver state */
	gint64				last_rx;					/* timestamp of last packet received */
	GList*				active_chats;				/* list of all our contacts we received messages from (active chats) */
	GList*				invites;					/* list of all the invites that we have received */

	/* groupchat */
	GList*				rooms;						/* active groupchat rooms */

	/* inline images */
	GHashTable*			iimages;					/* table which maps inline images (including emoticons) to purple's imgstore id's */
};


char* mxit_status_text( PurpleBuddy* buddy );
void mxit_enable_signals( struct MXitSession* session );

#ifdef	MXIT_LINK_CLICK
void mxit_register_uri_handler( void );
#endif


#endif		/* _MXIT_H_ */

