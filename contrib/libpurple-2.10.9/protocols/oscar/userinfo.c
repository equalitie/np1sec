/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

/*
 * Displaying various information about buddies.
 */

#include "encoding.h"
#include "oscar.h"

static gchar *
oscar_caps_to_string(guint64 caps)
{
	GString *str;
	const gchar *tmp;
	guint64 bit = 1;

	str = g_string_new("");

	if (!caps) {
		return NULL;
	} else while (bit <= OSCAR_CAPABILITY_LAST) {
		if (bit & caps) {
			switch (bit) {
			case OSCAR_CAPABILITY_BUDDYICON:
				tmp = _("Buddy Icon");
				break;
			case OSCAR_CAPABILITY_TALK:
				tmp = _("Voice");
				break;
			case OSCAR_CAPABILITY_DIRECTIM:
				tmp = _("AIM Direct IM");
				break;
			case OSCAR_CAPABILITY_CHAT:
				tmp = _("Chat");
				break;
			case OSCAR_CAPABILITY_GETFILE:
				tmp = _("Get File");
				break;
			case OSCAR_CAPABILITY_SENDFILE:
				tmp = _("Send File");
				break;
			case OSCAR_CAPABILITY_GAMES:
			case OSCAR_CAPABILITY_GAMES2:
				tmp = _("Games");
				break;
			case OSCAR_CAPABILITY_XTRAZ:
			case OSCAR_CAPABILITY_NEWCAPS:
				tmp = _("ICQ Xtraz");
				break;
			case OSCAR_CAPABILITY_ADDINS:
				tmp = _("Add-Ins");
				break;
			case OSCAR_CAPABILITY_SENDBUDDYLIST:
				tmp = _("Send Buddy List");
				break;
			case OSCAR_CAPABILITY_ICQ_DIRECT:
				tmp = _("ICQ Direct Connect");
				break;
			case OSCAR_CAPABILITY_APINFO:
				tmp = _("AP User");
				break;
			case OSCAR_CAPABILITY_ICQRTF:
				tmp = _("ICQ RTF");
				break;
			case OSCAR_CAPABILITY_EMPTY:
				tmp = _("Nihilist");
				break;
			case OSCAR_CAPABILITY_ICQSERVERRELAY:
				tmp = _("ICQ Server Relay");
				break;
			case OSCAR_CAPABILITY_UNICODEOLD:
				tmp = _("Old ICQ UTF8");
				break;
			case OSCAR_CAPABILITY_TRILLIANCRYPT:
				tmp = _("Trillian Encryption");
				break;
			case OSCAR_CAPABILITY_UNICODE:
				tmp = _("ICQ UTF8");
				break;
			case OSCAR_CAPABILITY_HIPTOP:
				tmp = _("Hiptop");
				break;
			case OSCAR_CAPABILITY_SECUREIM:
				tmp = _("Security Enabled");
				break;
			case OSCAR_CAPABILITY_VIDEO:
				tmp = _("Video Chat");
				break;
			/* Not actually sure about this one... WinAIM doesn't show anything */
			case OSCAR_CAPABILITY_ICHATAV:
				tmp = _("iChat AV");
				break;
			case OSCAR_CAPABILITY_LIVEVIDEO:
				tmp = _("Live Video");
				break;
			case OSCAR_CAPABILITY_CAMERA:
				tmp = _("Camera");
				break;
			case OSCAR_CAPABILITY_ICHAT_SCREENSHARE:
				tmp = _("Screen Sharing");
				break;
			default:
				tmp = NULL;
				break;
			}
			if (tmp)
				g_string_append_printf(str, "%s%s", (*(str->str) == '\0' ? "" : ", "), tmp);
		}
		bit <<= 1;
	}

	return g_string_free(str, FALSE);
}

static void
oscar_user_info_add_pair(PurpleNotifyUserInfo *user_info, const char *name, const char *value)
{
	if (value && value[0]) {
		purple_notify_user_info_add_pair(user_info, name, value);
	}
}

static void
oscar_user_info_convert_and_add(PurpleAccount *account, OscarData *od, PurpleNotifyUserInfo *user_info,
					const char *name, const char *value)
{
	gchar *utf8;

	if (value && value[0] && (utf8 = oscar_utf8_try_convert(account, od, value))) {
		purple_notify_user_info_add_pair(user_info, name, utf8);
		g_free(utf8);
	}
}

static void
oscar_user_info_convert_and_add_hyperlink(PurpleAccount *account, OscarData *od, PurpleNotifyUserInfo *user_info,
						const char *name, const char *value, const char *url_prefix)
{
	gchar *utf8;

	if (value && value[0] && (utf8 = oscar_utf8_try_convert(account, od, value))) {
		gchar *tmp = g_strdup_printf("<a href=\"%s%s\">%s</a>", url_prefix, utf8, utf8);
		purple_notify_user_info_add_pair(user_info, name, tmp);
		g_free(utf8);
		g_free(tmp);
	}
}

/**
 * @brief Append the status information to a user_info struct
 *
 * The returned information is HTML-ready, appropriately escaped, as all information in a user_info struct should be HTML.
 *
 * @param gc The PurpleConnection
 * @param user_info A PurpleNotifyUserInfo object to which status information will be added
 * @param b The PurpleBuddy whose status is desired. This or the aim_userinfo_t (or both) must be passed to oscar_user_info_append_status().
 * @param userinfo The aim_userinfo_t of the buddy whose status is desired. This or the PurpleBuddy (or both) must be passed to oscar_user_info_append_status().
 * @param use_html_status If TRUE, prefer HTML-formatted away message over plaintext available message.
 */
void
oscar_user_info_append_status(PurpleConnection *gc, PurpleNotifyUserInfo *user_info, PurpleBuddy *b, aim_userinfo_t *userinfo, gboolean use_html_status)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	OscarData *od;
	PurplePresence *presence = NULL;
	PurpleStatus *status = NULL;
	gchar *message = NULL, *itmsurl = NULL, *tmp;
	gboolean escaping_needed = TRUE;

	od = purple_connection_get_protocol_data(gc);

	if (b == NULL && userinfo == NULL)
		return;

	if (b == NULL)
		b = purple_find_buddy(purple_connection_get_account(gc), userinfo->bn);
	else
		userinfo = aim_locate_finduserinfo(od, purple_buddy_get_name(b));

	if (b) {
		presence = purple_buddy_get_presence(b);
		status = purple_presence_get_active_status(presence);
	}

	/* If we have both b and userinfo we favor userinfo, because if we're
	   viewing someone's profile then we want the HTML away message, and
	   the "message" attribute of the status contains only the plaintext
	   message. */
	if (userinfo) {
		if ((userinfo->flags & AIM_FLAG_AWAY) && use_html_status && userinfo->away_len > 0 && userinfo->away != NULL && userinfo->away_encoding != NULL) {
			/* Away message */
			message = oscar_encoding_to_utf8(userinfo->away_encoding, userinfo->away, userinfo->away_len);
			escaping_needed = FALSE;
		} else {
			/*
			 * Available message or non-HTML away message (because that's
			 * all we have right now.
			 */
			if ((userinfo->status != NULL) && userinfo->status[0] != '\0') {
				message = oscar_encoding_to_utf8(userinfo->status_encoding, userinfo->status, userinfo->status_len);
			}
#if defined (_WIN32) || defined (__APPLE__)
			if (userinfo->itmsurl && (userinfo->itmsurl[0] != '\0')) {
				itmsurl = oscar_encoding_to_utf8(userinfo->itmsurl_encoding, userinfo->itmsurl, userinfo->itmsurl_len);
			}
#endif
		}
	} else {
		message = g_strdup(purple_status_get_attr_string(status, "message"));
		itmsurl = g_strdup(purple_status_get_attr_string(status, "itmsurl"));
	}

	if (message) {
		tmp = oscar_util_format_string(message, purple_account_get_username(account));
		g_free(message);
		message = tmp;
		if (escaping_needed) {
			tmp = purple_markup_escape_text(message, -1);
			g_free(message);
			message = tmp;
		}
	}

	if (use_html_status && itmsurl) {
		tmp = g_strdup_printf("<a href=\"%s\">%s</a>", itmsurl, message);
		g_free(message);
		message = tmp;
	}

	if (b) {
		if (purple_presence_is_online(presence)) {
			gboolean is_away = ((status && !purple_status_is_available(status)) || (userinfo && (userinfo->flags & AIM_FLAG_AWAY)));
			if (oscar_util_valid_name_icq(purple_buddy_get_name(b)) || is_away || !message || !(*message)) {
				/* Append the status name for online ICQ statuses, away AIM statuses, and for all buddies with no message.
				 * If the status name and the message are the same, only show one. */
				const char *status_name = purple_status_get_name(status);
				if (status_name && message && !strcmp(status_name, message))
					status_name = NULL;

				tmp = g_strdup_printf("%s%s%s",
									   status_name ? status_name : "",
									   ((status_name && message) && *message) ? ": " : "",
									   (message && *message) ? message : "");
				g_free(message);
				message = tmp;
			}

		} else if (aim_ssi_waitingforauth(od->ssi.local,
			aim_ssi_itemlist_findparentname(od->ssi.local, purple_buddy_get_name(b)),
			purple_buddy_get_name(b)))
		{
			/* Note if an offline buddy is not authorized */
			tmp = g_strdup_printf("%s%s%s",
					_("Not Authorized"),
					(message && *message) ? ": " : "",
					(message && *message) ? message : "");
			g_free(message);
			message = tmp;
		} else {
			g_free(message);
			message = g_strdup(_("Offline"));
		}
	}

	if (presence) {
		const char *mood;
		const char *comment;
		char *description;
		status = purple_presence_get_status(presence, "mood");
		mood = icq_get_custom_icon_description(purple_status_get_attr_string(status, PURPLE_MOOD_NAME));
		if (mood) {
			comment = purple_status_get_attr_string(status, PURPLE_MOOD_COMMENT);
			if (comment) {
				char *escaped_comment = purple_markup_escape_text(comment, -1);
				description = g_strdup_printf("%s (%s)", _(mood), escaped_comment);
				g_free(escaped_comment);
			} else {
				description = g_strdup(_(mood));
			}
			purple_notify_user_info_add_pair(user_info, _("Mood"), description);
			g_free(description);
		}
	}

	purple_notify_user_info_add_pair(user_info, _("Status"), message);
	g_free(message);
}

void
oscar_user_info_append_extra_info(PurpleConnection *gc, PurpleNotifyUserInfo *user_info, PurpleBuddy *b, aim_userinfo_t *userinfo)
{
	OscarData *od;
	PurpleAccount *account;
	PurpleGroup *g = NULL;
	struct buddyinfo *bi = NULL;
	char *tmp;
	const char *bname = NULL, *gname = NULL;

	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);

	if ((user_info == NULL) || ((b == NULL) && (userinfo == NULL)))
		return;

	if (userinfo == NULL)
		userinfo = aim_locate_finduserinfo(od, purple_buddy_get_name(b));

	if (b == NULL)
		b = purple_find_buddy(account, userinfo->bn);

	if (b != NULL) {
		bname = purple_buddy_get_name(b);
		g = purple_buddy_get_group(b);
		gname = purple_group_get_name(g);
	}

	if (userinfo != NULL)
		bi = g_hash_table_lookup(od->buddyinfo, purple_normalize(account, userinfo->bn));

	if ((bi != NULL) && (bi->ipaddr != 0)) {
		tmp =  g_strdup_printf("%hhu.%hhu.%hhu.%hhu",
						(bi->ipaddr & 0xff000000) >> 24,
						(bi->ipaddr & 0x00ff0000) >> 16,
						(bi->ipaddr & 0x0000ff00) >> 8,
						(bi->ipaddr & 0x000000ff));
		oscar_user_info_add_pair(user_info, _("IP Address"), tmp);
		g_free(tmp);
	}

	if ((userinfo != NULL) && (userinfo->warnlevel != 0)) {
		tmp = g_strdup_printf("%d", (int)(userinfo->warnlevel/10.0 + .5));
		oscar_user_info_add_pair(user_info, _("Warning Level"), tmp);
		g_free(tmp);
	}

	if ((b != NULL) && (bname != NULL) && (g != NULL) && (gname != NULL)) {
		tmp = aim_ssi_getcomment(od->ssi.local, gname, bname);
		if (tmp != NULL) {
			char *tmp2 = g_markup_escape_text(tmp, strlen(tmp));
			g_free(tmp);

			oscar_user_info_convert_and_add(account, od, user_info, _("Buddy Comment"), tmp2);
			g_free(tmp2);
		}
	}
}

void
oscar_user_info_display_error(OscarData *od, guint16 error_reason, gchar *buddy)
{
	PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
	gchar *buf = g_strdup_printf(_("User information not available: %s"), oscar_get_msgerr_reason(error_reason));
	purple_notify_user_info_add_pair(user_info, NULL, buf);
	purple_notify_userinfo(od->gc, buddy, user_info, NULL, NULL);
	purple_notify_user_info_destroy(user_info);
	purple_conv_present_error(buddy, purple_connection_get_account(od->gc), buf);
	g_free(buf);
}

void
oscar_user_info_display_icq(OscarData *od, struct aim_icq_info *info)
{
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	PurpleBuddy *buddy;
	struct buddyinfo *bi;
	gchar who[16];
	PurpleNotifyUserInfo *user_info;

	if (!info->uin)
		return;

	user_info = purple_notify_user_info_new();

	g_snprintf(who, sizeof(who), "%u", info->uin);
	buddy = purple_find_buddy(account, who);
	if (buddy != NULL)
		bi = g_hash_table_lookup(od->buddyinfo, purple_normalize(account, purple_buddy_get_name(buddy)));
	else
		bi = NULL;

	purple_notify_user_info_add_pair(user_info, _("UIN"), who);
	oscar_user_info_convert_and_add(account, od, user_info, _("Nick"), info->nick);
	if ((bi != NULL) && (bi->ipaddr != 0)) {
		char *tstr =  g_strdup_printf("%hhu.%hhu.%hhu.%hhu",
						(bi->ipaddr & 0xff000000) >> 24,
						(bi->ipaddr & 0x00ff0000) >> 16,
						(bi->ipaddr & 0x0000ff00) >> 8,
						(bi->ipaddr & 0x000000ff));
		purple_notify_user_info_add_pair(user_info, _("IP Address"), tstr);
		g_free(tstr);
	}
	oscar_user_info_convert_and_add(account, od, user_info, _("First Name"), info->first);
	oscar_user_info_convert_and_add(account, od, user_info, _("Last Name"), info->last);
	oscar_user_info_convert_and_add_hyperlink(account, od, user_info, _("Email Address"), info->email, "mailto:");
	if (info->numaddresses && info->email2) {
		int i;
		for (i = 0; i < info->numaddresses; i++) {
			oscar_user_info_convert_and_add_hyperlink(account, od, user_info, _("Email Address"), info->email2[i], "mailto:");
		}
	}
	oscar_user_info_convert_and_add(account, od, user_info, _("Mobile Phone"), info->mobile);

	if (info->gender != 0)
		purple_notify_user_info_add_pair(user_info, _("Gender"), (info->gender == 1 ? _("Female") : _("Male")));

	if ((info->birthyear > 1900) && (info->birthmonth > 0) && (info->birthday > 0)) {
		/* Initialize the struct properly or strftime() will crash
		 * under some conditions (e.g. Debian sarge w/ LANG=en_HK). */
		time_t t = time(NULL);
		struct tm *tm = localtime(&t);

		tm->tm_mday = (int)info->birthday;
		tm->tm_mon  = (int)info->birthmonth - 1;
		tm->tm_year = (int)info->birthyear - 1900;

		/* Ignore dst setting of today to avoid timezone shift between 
		 * dates in summer and winter time. */
		tm->tm_isdst = -1;

		/* To be 100% sure that the fields are re-normalized.
		 * If you're sure strftime() ALWAYS does this EVERYWHERE,
		 * feel free to remove it.  --rlaager */
		mktime(tm);

		oscar_user_info_convert_and_add(account, od, user_info, _("Birthday"), purple_date_format_short(tm));
	}
	if ((info->age > 0) && (info->age < 255)) {
		char age[5];
		snprintf(age, sizeof(age), "%hhd", info->age);
		purple_notify_user_info_add_pair(user_info, _("Age"), age);
	}
	oscar_user_info_convert_and_add_hyperlink(account, od, user_info, _("Personal Web Page"), info->email, "");
	if (buddy != NULL)
		oscar_user_info_append_status(gc, user_info, buddy, /* aim_userinfo_t */ NULL, /* use_html_status */ TRUE);

	oscar_user_info_convert_and_add(account, od, user_info, _("Additional Information"), info->info);
	purple_notify_user_info_add_section_break(user_info);

	if ((info->homeaddr && (info->homeaddr[0])) || (info->homecity && info->homecity[0]) || (info->homestate && info->homestate[0]) || (info->homezip && info->homezip[0])) {
		purple_notify_user_info_add_section_header(user_info, _("Home Address"));

		oscar_user_info_convert_and_add(account, od, user_info, _("Address"), info->homeaddr);
		oscar_user_info_convert_and_add(account, od, user_info, _("City"), info->homecity);
		oscar_user_info_convert_and_add(account, od, user_info, _("State"), info->homestate);
		oscar_user_info_convert_and_add(account, od, user_info, _("Zip Code"), info->homezip);
	}
	if ((info->workaddr && info->workaddr[0]) || (info->workcity && info->workcity[0]) || (info->workstate && info->workstate[0]) || (info->workzip && info->workzip[0])) {
		purple_notify_user_info_add_section_header(user_info, _("Work Address"));

		oscar_user_info_convert_and_add(account, od, user_info, _("Address"), info->workaddr);
		oscar_user_info_convert_and_add(account, od, user_info, _("City"), info->workcity);
		oscar_user_info_convert_and_add(account, od, user_info, _("State"), info->workstate);
		oscar_user_info_convert_and_add(account, od, user_info, _("Zip Code"), info->workzip);
	}
	if ((info->workcompany && info->workcompany[0]) || (info->workdivision && info->workdivision[0]) || (info->workposition && info->workposition[0]) || (info->workwebpage && info->workwebpage[0])) {
		purple_notify_user_info_add_section_header(user_info, _("Work Information"));

		oscar_user_info_convert_and_add(account, od, user_info, _("Company"), info->workcompany);
		oscar_user_info_convert_and_add(account, od, user_info, _("Division"), info->workdivision);
		oscar_user_info_convert_and_add(account, od, user_info, _("Position"), info->workposition);
		oscar_user_info_convert_and_add_hyperlink(account, od, user_info, _("Web Page"), info->email, "");
	}

	purple_notify_userinfo(gc, who, user_info, NULL, NULL);
	purple_notify_user_info_destroy(user_info);
}

void
oscar_user_info_display_aim(OscarData *od, aim_userinfo_t *userinfo)
{
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
	gchar *tmp = NULL, *info_utf8 = NULL, *base_profile_url = NULL;

	oscar_user_info_append_status(gc, user_info, /* PurpleBuddy */ NULL, userinfo, /* use_html_status */ TRUE);

	if ((userinfo->present & AIM_USERINFO_PRESENT_IDLE) && userinfo->idletime != 0) {
		tmp = purple_str_seconds_to_string(userinfo->idletime*60);
		oscar_user_info_add_pair(user_info, _("Idle"), tmp);
		g_free(tmp);
	}

	oscar_user_info_append_extra_info(gc, user_info, NULL, userinfo);

	if ((userinfo->present & AIM_USERINFO_PRESENT_ONLINESINCE) && !oscar_util_valid_name_sms(userinfo->bn)) {
		/* An SMS contact is always online; its Online Since value is not useful */
		time_t t = userinfo->onlinesince;
		oscar_user_info_add_pair(user_info, _("Online Since"), purple_date_format_full(localtime(&t)));
	}

	if (userinfo->present & AIM_USERINFO_PRESENT_MEMBERSINCE) {
		time_t t = userinfo->membersince;
		oscar_user_info_add_pair(user_info, _("Member Since"), purple_date_format_full(localtime(&t)));
	}

	if (userinfo->capabilities != 0) {
		tmp = oscar_caps_to_string(userinfo->capabilities);
		oscar_user_info_add_pair(user_info, _("Capabilities"), tmp);
		g_free(tmp);
	}

	/* Info */
	if ((userinfo->info_len > 0) && (userinfo->info != NULL) && (userinfo->info_encoding != NULL)) {
		info_utf8 = oscar_encoding_to_utf8(userinfo->info_encoding, userinfo->info, userinfo->info_len);
		tmp = oscar_util_format_string(info_utf8, purple_account_get_username(account));
		purple_notify_user_info_add_section_break(user_info);
		oscar_user_info_add_pair(user_info, _("Profile"), tmp);
		g_free(tmp);
		g_free(info_utf8);
	}

	purple_notify_user_info_add_section_break(user_info);
	base_profile_url = oscar_util_valid_name_icq(userinfo->bn) ? "http://www.icq.com/people" : "http://profiles.aim.com";
	tmp = g_strdup_printf("<a href=\"%s/%s\">%s</a>",
			base_profile_url, purple_normalize(account, userinfo->bn), _("View web profile"));
	purple_notify_user_info_add_pair(user_info, NULL, tmp);
	g_free(tmp);

	purple_notify_userinfo(gc, userinfo->bn, user_info, NULL, NULL);
	purple_notify_user_info_destroy(user_info);
}
