/**
 * @file backend-fs2.h Farsight 2 backend for media API
 * @ingroup core
 */

/* purple
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

/*
 * This file should not yet be part of libpurple's API.
 * It should remain internal only for now.
 */

#ifndef _MEDIA_BACKEND_FS2_H_
#define _MEDIA_BACKEND_FS2_H_

#include <glib-object.h>

G_BEGIN_DECLS

#define PURPLE_TYPE_MEDIA_BACKEND_FS2            (purple_media_backend_fs2_get_type())
#define PURPLE_IS_MEDIA_BACKEND_FS2(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), PURPLE_TYPE_MEDIA_BACKEND_FS2))
#define PURPLE_IS_MEDIA_BACKEND_FS2_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), PURPLE_TYPE_MEDIA_BACKEND_FS2))
#define PURPLE_MEDIA_BACKEND_FS2(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), PURPLE_TYPE_MEDIA_BACKEND_FS2, PurpleMediaBackendFs2))
#define PURPLE_MEDIA_BACKEND_FS2_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), PURPLE_TYPE_MEDIA_BACKEND_FS2, PurpleMediaBackendFs2))
#define PURPLE_MEDIA_BACKEND_FS2_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), PURPLE_TYPE_MEDIA_BACKEND_FS2, PurpleMediaBackendFs2))

/** An opaque structure representing the Farsight 2 media backend. */
typedef struct _PurpleMediaBackendFs2 PurpleMediaBackendFs2;

/**
 * Gets the type of the Farsight 2 media backend object.
 *
 * @return The Farsight 2 media backend's GType
 *
 * @since 2.7.0
 */
GType purple_media_backend_fs2_get_type(void);

#ifdef USE_GSTREAMER
/*
 * Temporary function in order to be able to test while
 * integrating with PurpleMedia
 */
#include <gst/gst.h>
GstElement *purple_media_backend_fs2_get_src(
		PurpleMediaBackendFs2 *self,
		const gchar *sess_id);
GstElement *purple_media_backend_fs2_get_tee(
		PurpleMediaBackendFs2 *self,
		const gchar *sess_id, const gchar *who);
void purple_media_backend_fs2_set_input_volume(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, double level);
void purple_media_backend_fs2_set_output_volume(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, const gchar *who, double level);
/* end tmp */
#endif /* USE_GSTREAMER */

G_END_DECLS

#endif /* _MEDIA_BACKEND_FS2_H_ */
