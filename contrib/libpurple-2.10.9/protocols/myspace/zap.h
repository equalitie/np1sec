/* MySpaceIM Protocol Plugin - zap support
 *
 * Copyright (C) 2007, Jeff Connelly <jeff2@soc.pidgin.im>
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

#ifndef _MYSPACE_ZAP_H
#define _MYSPACE_ZAP_H

GList *msim_attention_types(PurpleAccount *acct);
gboolean msim_send_attention(PurpleConnection *gc, const gchar *username, guint code);
GList *msim_blist_node_menu(PurpleBlistNode *node);
gboolean msim_incoming_zap(MsimSession *session, MsimMessage *msg);

#endif /* !_MYSPACE_ZAP_H */
