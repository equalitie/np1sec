/**
 * @file iceudp.h
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

#ifndef PURPLE_JABBER_JINGLE_ICEUDP_H
#define PURPLE_JABBER_JINGLE_ICEUDP_H

#include <glib.h>
#include <glib-object.h>

#include "transport.h"

G_BEGIN_DECLS

#define JINGLE_TYPE_ICEUDP            (jingle_iceudp_get_type())
#define JINGLE_TYPE_ICEUDP_CANDIDATE  (jingle_iceudp_candidate_get_type())
#define JINGLE_ICEUDP(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_ICEUDP, JingleIceUdp))
#define JINGLE_ICEUDP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_ICEUDP, JingleIceUdpClass))
#define JINGLE_IS_ICEUDP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_ICEUDP))
#define JINGLE_IS_ICEUDP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_ICEUDP))
#define JINGLE_ICEUDP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_ICEUDP, JingleIceUdpClass))

/** @copydoc _JingleIceUdp */
typedef struct _JingleIceUdp JingleIceUdp;
/** @copydoc _JingleIceUdpClass */
typedef struct _JingleIceUdpClass JingleIceUdpClass;
/** @copydoc _JingleIceUdpPrivate */
typedef struct _JingleIceUdpPrivate JingleIceUdpPrivate;
/** @copydoc _JingleIceUdpCandidate */
typedef struct _JingleIceUdpCandidate JingleIceUdpCandidate;

/** The iceudp class */
struct _JingleIceUdpClass
{
	JingleTransportClass parent_class;     /**< The parent class. */

	xmlnode *(*to_xml) (JingleTransport *transport, xmlnode *content, JingleActionType action);
	JingleTransport *(*parse) (xmlnode *transport);
};

/** The iceudp class's private data */
struct _JingleIceUdp
{
	JingleTransport parent;                /**< The parent of this object. */
	JingleIceUdpPrivate *priv;      /**< The private data of this object. */
};

struct _JingleIceUdpCandidate
{
	guint component;
	gchar *foundation;
	guint generation;
	gchar *id;
	gchar *ip;
	guint network;
	guint port;
	guint priority;
	gchar *protocol;
	gchar *reladdr;
	guint relport;
	gchar *type;

	gchar *username;
	gchar *password;

	gboolean rem_known;	/* TRUE if the remote side knows
				 * about this candidate */
};

#ifdef __cplusplus
extern "C" {
#endif

GType jingle_iceudp_candidate_get_type(void);

/**
 * Gets the iceudp class's GType
 *
 * @return The iceudp class's GType.
 */
GType jingle_iceudp_get_type(void);

JingleIceUdpCandidate *jingle_iceudp_candidate_new(guint component,
		const gchar *foundation, guint generation, const gchar *id,
		const gchar *ip, guint network, guint port, guint priority,
		const gchar *protocol, const gchar *type,
		const gchar *username, const gchar *password);
void jingle_iceudp_add_local_candidate(JingleIceUdp *iceudp, JingleIceUdpCandidate *candidate);
GList *jingle_iceudp_get_remote_candidates(JingleIceUdp *iceudp);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* PURPLE_JABBER_JINGLE_ICEUDP_H */

