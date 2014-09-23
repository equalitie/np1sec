/**
 * @file enum-types.c Enum types for Media API
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

#include "enum-types.h"

/*
 * PurpleMediaCandidateType
 */

GType
purple_media_candidate_type_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GEnumValue values[] = {
			{ PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
					"PURPLE_MEDIA_CANDIDATE_TYPE_HOST",
					"host" },
			{ PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX,
					"PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX",
					"srflx" },
			{ PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX,
					"PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX",
					"prflx" },
			{ PURPLE_MEDIA_CANDIDATE_TYPE_RELAY,
					"PURPLE_MEDIA_CANDIDATE_TYPE_RELAY",
					"relay" },
			{ PURPLE_MEDIA_CANDIDATE_TYPE_MULTICAST,
					"PURPLE_MEDIA_CANDIDATE_TYPE_MULTICAST",
					"multicast" },
			{ 0, NULL, NULL }
		};
		type = g_enum_register_static("PurpleMediaCandidateType",
				values);
	}
	return type;
}

/*
 * PurpleMediaCaps
 */

GType
purple_media_caps_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GEnumValue values[] = {
			{ PURPLE_MEDIA_CAPS_NONE,
					"PURPLE_MEDIA_CAPS_NONE", "none" },
			{ PURPLE_MEDIA_CAPS_AUDIO,
					"PURPLE_MEDIA_CAPS_AUDIO", "audio" },
			{ PURPLE_MEDIA_CAPS_AUDIO_SINGLE_DIRECTION,
					"PURPLE_MEDIA_CAPS_AUDIO_SINGLE_DIRECTION",
					"audio-single-direction" },
			{ PURPLE_MEDIA_CAPS_VIDEO,
					"PURPLE_MEDIA_CAPS_VIDEO", "video" },
			{ PURPLE_MEDIA_CAPS_VIDEO_SINGLE_DIRECTION,
					"PURPLE_MEDIA_CAPS_VIDEO_SINGLE_DIRECTION",
					"video-single-direction" },
			{ PURPLE_MEDIA_CAPS_AUDIO_VIDEO,
					"PURPLE_MEDIA_CAPS_AUDIO_VIDEO",
					"audio-video" },
			{ PURPLE_MEDIA_CAPS_MODIFY_SESSION,
					"PURPLE_MEDIA_CAPS_MODIFY_SESSION",
					"modify-session" },
			{ PURPLE_MEDIA_CAPS_CHANGE_DIRECTION,
					"PURPLE_MEDIA_CAPS_CHANGE_DIRECTION",
					"change-direction" },
			{ 0, NULL, NULL }
		};
		type = g_enum_register_static("PurpleMediaCaps", values);
	}
	return type;
}

/*
 * PurpleMediaInfoType
 */

GType
purple_media_info_type_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GEnumValue values[] = {
			{ PURPLE_MEDIA_INFO_HANGUP,
					"PURPLE_MEDIA_INFO_HANGUP", "hangup" },
			{ PURPLE_MEDIA_INFO_ACCEPT,
					"PURPLE_MEDIA_INFO_ACCEPT", "accept" },
			{ PURPLE_MEDIA_INFO_REJECT,
					"PURPLE_MEDIA_INFO_REJECT", "reject" },
			{ PURPLE_MEDIA_INFO_MUTE,
					"PURPLE_MEDIA_INFO_MUTE", "mute" },
			{ PURPLE_MEDIA_INFO_UNMUTE,
					"PURPLE_MEDIA_INFO_UNMUTE", "unmute" },
			{ PURPLE_MEDIA_INFO_PAUSE,
					"PURPLE_MEDIA_INFO_PAUSE", "pause" },
			{ PURPLE_MEDIA_INFO_UNPAUSE,
					"PURPLE_MEDIA_INFO_UNPAUSE", "unpause" },
			{ PURPLE_MEDIA_INFO_HOLD,
					"PURPLE_MEDIA_INFO_HOLD", "hold" },
			{ PURPLE_MEDIA_INFO_UNHOLD,
					"PURPLE_MEDIA_INFO_HOLD", "unhold" },
			{ 0, NULL, NULL }
		};
		type = g_enum_register_static("PurpleMediaInfoType", values);
	}
	return type;
}

/*
 * PurpleMediaNetworkProtocol
 */

GType
purple_media_network_protocol_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GEnumValue values[] = {
			{ PURPLE_MEDIA_NETWORK_PROTOCOL_UDP,
					"PURPLE_MEDIA_NETWORK_PROTOCOL_UDP",
					"udp" },
			{ PURPLE_MEDIA_NETWORK_PROTOCOL_TCP,
					"PURPLE_MEDIA_NETWORK_PROTOCOL_TCP",
					"tcp" },
			{ 0, NULL, NULL }
		};
		type = g_enum_register_static("PurpleMediaNetworkProtocol",
				values);
	}
	return type;
}

/*
 * PurpleMediaSessionType
 */

GType
purple_media_session_type_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GFlagsValue values[] = {
			{ PURPLE_MEDIA_NONE,
				"PURPLE_MEDIA_NONE", "none" },
			{ PURPLE_MEDIA_RECV_AUDIO,
				"PURPLE_MEDIA_RECV_AUDIO", "recv-audio" },
			{ PURPLE_MEDIA_SEND_AUDIO,
				"PURPLE_MEDIA_SEND_AUDIO", "send-audio" },
			{ PURPLE_MEDIA_RECV_VIDEO,
				"PURPLE_MEDIA_RECV_VIDEO", "recv-video" },
			{ PURPLE_MEDIA_SEND_VIDEO,
				"PURPLE_MEDIA_SEND_VIDEO", "send-audio" },
			{ PURPLE_MEDIA_AUDIO,
				"PURPLE_MEDIA_AUDIO", "audio" },
			{ PURPLE_MEDIA_VIDEO,
				"PURPLE_MEDIA_VIDEO", "video" },
			{ 0, NULL, NULL }
		};
		type = g_flags_register_static(
				"PurpleMediaSessionType", values);
	}
	return type;
}

/*
 * PurpleMediaState
 */

GType
purple_media_state_changed_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GEnumValue values[] = {
			{ PURPLE_MEDIA_STATE_NEW,
				"PURPLE_MEDIA_STATE_NEW", "new" },
			{ PURPLE_MEDIA_STATE_CONNECTED,
				"PURPLE_MEDIA_STATE_CONNECTED", "connected" },
			{ PURPLE_MEDIA_STATE_END,
				"PURPLE_MEDIA_STATE_END", "end" },
			{ 0, NULL, NULL }
		};
		type = g_enum_register_static("PurpleMediaState", values);
	}
	return type;
}

