/*
 * nmrtf.h
 *
 * Copyright (c) 2004 Novell, Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA	02111-1301	USA
 *
 */

#ifndef __NMRTF_H__
#define __NMRTF_H__

typedef struct _NMRtfContext NMRtfContext;

NMRtfContext *nm_rtf_init(void);
char *nm_rtf_strip_formatting(NMRtfContext *ctx, const char *input);
void nm_rtf_deinit(NMRtfContext *ctx);

#endif
