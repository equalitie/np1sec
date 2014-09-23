/**
 * @file rtp.h
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

#ifndef PURPLE_JABBER_JINGLE_RTP_H
#define PURPLE_JABBER_JINGLE_RTP_H

#include "config.h"

#ifdef USE_VV

#include <glib.h>
#include <glib-object.h>

#include "content.h"
#include "media.h"
#include "xmlnode.h"

G_BEGIN_DECLS

#define JINGLE_TYPE_RTP            (jingle_rtp_get_type())
#define JINGLE_RTP(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_RTP, JingleRtp))
#define JINGLE_RTP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_RTP, JingleRtpClass))
#define JINGLE_IS_RTP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_RTP))
#define JINGLE_IS_RTP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_RTP))
#define JINGLE_RTP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_RTP, JingleRtpClass))

/** @copydoc _JingleRtp */
typedef struct _JingleRtp JingleRtp;
/** @copydoc _JingleRtpClass */
typedef struct _JingleRtpClass JingleRtpClass;
/** @copydoc _JingleRtpPrivate */
typedef struct _JingleRtpPrivate JingleRtpPrivate;

/** The rtp class */
struct _JingleRtpClass
{
	JingleContentClass parent_class;     /**< The parent class. */
};

/** The rtp class's private data */
struct _JingleRtp
{
	JingleContent parent;                /**< The parent of this object. */
	JingleRtpPrivate *priv;      /**< The private data of this object. */
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Gets the rtp class's GType
 *
 * @return The rtp class's GType.
 */
GType jingle_rtp_get_type(void);

gchar *jingle_rtp_get_media_type(JingleContent *content);
gchar *jingle_rtp_get_ssrc(JingleContent *content);

gboolean jingle_rtp_initiate_media(JabberStream *js,
				   const gchar *who,
				   PurpleMediaSessionType type);
void jingle_rtp_terminate_session(JabberStream *js, const gchar *who);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* USE_VV */

#endif /* PURPLE_JABBER_JINGLE_RTP_H */

