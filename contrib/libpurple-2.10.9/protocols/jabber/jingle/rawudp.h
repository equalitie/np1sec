/**
 * @file rawudp.h
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

#ifndef PURPLE_JABBER_JINGLE_RAWUDP_H
#define PURPLE_JABBER_JINGLE_RAWUDP_H

#include <glib.h>
#include <glib-object.h>

#include "transport.h"

G_BEGIN_DECLS

#define JINGLE_TYPE_RAWUDP            (jingle_rawudp_get_type())
#define JINGLE_TYPE_RAWUDP_CANDIDATE  (jingle_rawudp_candidate_get_type())
#define JINGLE_RAWUDP(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_RAWUDP, JingleRawUdp))
#define JINGLE_RAWUDP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_RAWUDP, JingleRawUdpClass))
#define JINGLE_IS_RAWUDP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_RAWUDP))
#define JINGLE_IS_RAWUDP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_RAWUDP))
#define JINGLE_RAWUDP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_RAWUDP, JingleRawUdpClass))

/** @copydoc _JingleRawUdp */
typedef struct _JingleRawUdp JingleRawUdp;
/** @copydoc _JingleRawUdpClass */
typedef struct _JingleRawUdpClass JingleRawUdpClass;
/** @copydoc _JingleRawUdpPrivate */
typedef struct _JingleRawUdpPrivate JingleRawUdpPrivate;
/** @copydoc _JingleRawUdpCandidate */
typedef struct _JingleRawUdpCandidate JingleRawUdpCandidate;

/** The rawudp class */
struct _JingleRawUdpClass
{
	JingleTransportClass parent_class;     /**< The parent class. */

	xmlnode *(*to_xml) (JingleTransport *transport, xmlnode *content, JingleActionType action);
	JingleTransport *(*parse) (xmlnode *transport);
};

/** The rawudp class's private data */
struct _JingleRawUdp
{
	JingleTransport parent;                /**< The parent of this object. */
	JingleRawUdpPrivate *priv;      /**< The private data of this object. */
};

struct _JingleRawUdpCandidate
{
	guint generation;
	guint component;
	gchar *id;
	gchar *ip;
	guint port;

	gboolean rem_known;	/* TRUE if the remote side knows
				 * about this candidate */
};

#ifdef __cplusplus
extern "C" {
#endif

GType jingle_rawudp_candidate_get_type(void);

/**
 * Gets the rawudp class's GType
 *
 * @return The rawudp class's GType.
 */
GType jingle_rawudp_get_type(void);

JingleRawUdpCandidate *jingle_rawudp_candidate_new(const gchar *id,
		guint generation, guint component, const gchar *ip, guint port);
void jingle_rawudp_add_local_candidate(JingleRawUdp *rawudp, JingleRawUdpCandidate *candidate);
GList *jingle_rawudp_get_remote_candidates(JingleRawUdp *rawudp);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* PURPLE_JABBER_JINGLE_RAWUDP_H */

