/**
 * @file backend-iface.c Interface for media backend
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

#include "backend-iface.h"

#include "marshallers.h"

enum {
	S_ERROR,
	CANDIDATES_PREPARED,
	CODECS_CHANGED,
	NEW_CANDIDATE,
	ACTIVE_CANDIDATE_PAIR,
	LAST_SIGNAL
};

static guint purple_media_backend_signals[LAST_SIGNAL] = {0};

static void
purple_media_backend_base_init(gpointer iface)
{
	static gboolean is_initialized = FALSE;

	if (is_initialized)
		return;

	g_object_interface_install_property(iface,
			g_param_spec_string("conference-type",
			"Conference Type",
			"The type of conference that this backend "
			"has been created to provide.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));
	g_object_interface_install_property(iface,
			g_param_spec_object("media",
			"Purple Media",
			"The media object that this backend is bound to.",
			PURPLE_TYPE_MEDIA,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	purple_media_backend_signals[S_ERROR] =
			g_signal_new("error", G_TYPE_FROM_CLASS(iface),
			G_SIGNAL_RUN_LAST, 0, NULL, NULL,
			g_cclosure_marshal_VOID__STRING,
			G_TYPE_NONE, 1, G_TYPE_STRING);
	purple_media_backend_signals[CANDIDATES_PREPARED] =
			g_signal_new("candidates-prepared",
			G_TYPE_FROM_CLASS(iface),
			G_SIGNAL_RUN_LAST, 0, NULL, NULL,
			purple_smarshal_VOID__STRING_STRING,
			G_TYPE_NONE, 2, G_TYPE_STRING,
			G_TYPE_STRING);
	purple_media_backend_signals[CODECS_CHANGED] =
			g_signal_new("codecs-changed",
			G_TYPE_FROM_CLASS(iface),
			G_SIGNAL_RUN_LAST, 0, NULL, NULL,
			g_cclosure_marshal_VOID__STRING,
			G_TYPE_NONE, 1, G_TYPE_STRING);
	purple_media_backend_signals[NEW_CANDIDATE] =
			g_signal_new("new-candidate",
			G_TYPE_FROM_CLASS(iface),
			G_SIGNAL_RUN_LAST, 0, NULL, NULL,
			purple_smarshal_VOID__POINTER_POINTER_OBJECT,
			G_TYPE_NONE, 3, G_TYPE_POINTER,
			G_TYPE_POINTER, PURPLE_TYPE_MEDIA_CANDIDATE);
	purple_media_backend_signals[ACTIVE_CANDIDATE_PAIR] =
			g_signal_new("active-candidate-pair",
			G_TYPE_FROM_CLASS(iface),
			G_SIGNAL_RUN_LAST, 0, NULL, NULL,
			purple_smarshal_VOID__STRING_STRING_OBJECT_OBJECT,
			G_TYPE_NONE, 4, G_TYPE_STRING, G_TYPE_STRING,
			PURPLE_TYPE_MEDIA_CANDIDATE,
			PURPLE_TYPE_MEDIA_CANDIDATE);

	is_initialized = TRUE;
}

GType
purple_media_backend_get_type(void)
{
	static GType iface_type = 0;
	if (iface_type == 0) {
		static const GTypeInfo info = {
			sizeof(PurpleMediaBackendIface),
			purple_media_backend_base_init,
			NULL,
			NULL,
			NULL,
			NULL,
			0,
			0,
			NULL,
			NULL
		};

		iface_type = g_type_register_static (G_TYPE_INTERFACE,
				"PurpleMediaBackend", &info, 0);
	}

	return iface_type;
}

gboolean
purple_media_backend_add_stream(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *who,
		PurpleMediaSessionType type, gboolean initiator,
		const gchar *transmitter,
		guint num_params, GParameter *params)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND(self), FALSE);
	return PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->add_stream(self,
			sess_id, who, type, initiator, transmitter,
			num_params, params);
}

void
purple_media_backend_add_remote_candidates(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant,
		GList *remote_candidates)
{
	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND(self));
	PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->add_remote_candidates(self,
			sess_id, participant, remote_candidates);
}

gboolean
purple_media_backend_codecs_ready(PurpleMediaBackend *self,
		const gchar *sess_id)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND(self), FALSE);
	return PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->codecs_ready(self,
			sess_id);
}

GList *
purple_media_backend_get_codecs(PurpleMediaBackend *self,
		const gchar *sess_id)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND(self), NULL);
	return PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->get_codecs(self,
			sess_id);
}

GList *
purple_media_backend_get_local_candidates(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND(self), NULL);
	return PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->
			get_local_candidates(self,
			sess_id, participant);
}

gboolean
purple_media_backend_set_remote_codecs(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant,
		GList *codecs)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND(self), FALSE);
	return PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->set_remote_codecs(
			self, sess_id, participant, codecs);
}

gboolean
purple_media_backend_set_send_codec(PurpleMediaBackend *self,
		const gchar *sess_id, PurpleMediaCodec *codec)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND(self), FALSE);
	return PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->set_send_codec(self,
			sess_id, codec);
}

void
purple_media_backend_set_params(PurpleMediaBackend *self,
		guint num_params, GParameter *params)
{
	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND(self));
	PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->set_params(self, num_params, params);
}

const gchar **
purple_media_backend_get_available_params(PurpleMediaBackend *self)
{
	static const gchar *NULL_ARRAY[] = { NULL };

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND(self), NULL_ARRAY);
	return PURPLE_MEDIA_BACKEND_GET_INTERFACE(self)->get_available_params();
}
