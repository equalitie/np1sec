/* MySpaceIM Protocol Plugin - markup
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

#ifndef _MYSPACE_MARKUP_H
#define _MYSPACE_MARKUP_H

/* High-level msim markup <=> Purple html conversion functions. */
gchar *msim_markup_to_html(MsimSession *, const gchar *raw);
gchar *html_to_msim_markup(MsimSession *, const gchar *raw);

#endif /* !_MYSPACE_MARKUP_H */
