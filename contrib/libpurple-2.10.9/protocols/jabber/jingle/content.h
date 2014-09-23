/**
 * @file content.h
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

#ifndef PURPLE_JABBER_JINGLE_CONTENT_H
#define PURPLE_JABBER_JINGLE_CONTENT_H


#include "jabber.h"
#include "jingle.h"
#include "session.h"
#include "transport.h"

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define JINGLE_TYPE_CONTENT            (jingle_content_get_type())
#define JINGLE_CONTENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_CONTENT, JingleContent))
#define JINGLE_CONTENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_CONTENT, JingleContentClass))
#define JINGLE_IS_CONTENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_CONTENT))
#define JINGLE_IS_CONTENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_CONTENT))
#define JINGLE_CONTENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_CONTENT, JingleContentClass))

/** @copydoc _JingleContent */
typedef struct _JingleContent JingleContent;
/** @copydoc _JingleContentClass */
typedef struct _JingleContentClass JingleContentClass;
/** @copydoc _JingleContentPrivate */
typedef struct _JingleContentPrivate JingleContentPrivate;

/** The content class */
struct _JingleContentClass
{
	GObjectClass parent_class;     /**< The parent class. */

	xmlnode *(*to_xml) (JingleContent *content, xmlnode *jingle, JingleActionType action);
	JingleContent *(*parse) (xmlnode *content);
	void (*handle_action) (JingleContent *content, xmlnode *xmlcontent, JingleActionType action);
	const gchar *description_type;
};

/** The content class's private data */
struct _JingleContent
{
	GObject parent;                /**< The parent of this object. */
	JingleContentPrivate *priv;      /**< The private data of this object. */
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Gets the content class's GType
 *
 * @return The content class's GType.
 */
GType jingle_content_get_type(void);

JingleContent *jingle_content_create(const gchar *type, const gchar *creator,
		const gchar *disposition, const gchar *name,
		const gchar *senders, JingleTransport *transport);

JingleSession *jingle_content_get_session(JingleContent *content);
const gchar *jingle_content_get_description_type(JingleContent *content);
gchar *jingle_content_get_creator(JingleContent *content);
gchar *jingle_content_get_disposition(JingleContent *content);
gchar *jingle_content_get_name(JingleContent *content);
gchar *jingle_content_get_senders(JingleContent *content);
JingleTransport *jingle_content_get_transport(JingleContent *content);
JingleTransport *jingle_content_get_pending_transport(JingleContent *content);

void jingle_content_set_session(JingleContent *content, JingleSession *session);
void jingle_content_set_pending_transport(JingleContent *content, JingleTransport *transport);
void jingle_content_accept_transport(JingleContent *content);
void jingle_content_remove_pending_transport(JingleContent *content);
void jingle_content_modify(JingleContent *content, const gchar *senders);

#define jingle_content_create_content_accept(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_ACCEPT)
#define jingle_content_create_content_add(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_ADD)
#define jingle_content_create_content_modify(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_MODIFY)
#define jingle_content_create_content_remove(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_REMOVE)

JingleContent *jingle_content_parse(xmlnode *content);
xmlnode *jingle_content_to_xml(JingleContent *content, xmlnode *jingle, JingleActionType action);
void jingle_content_handle_action(JingleContent *content, xmlnode *xmlcontent, JingleActionType action);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* PURPLE_JABBER_JINGLE_CONTENT_H */

