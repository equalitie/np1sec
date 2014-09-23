/**
 * @file tcl_purple.h Purple Tcl definitions
 *
 * purple
 *
 * Copyright (C) 2003 Ethan Blanton <eblanton@cs.purdue.edu>
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

#ifndef _PURPLE_TCL_PURPLE_H_
#define _PURPLE_TCL_PURPLE_H_

#include <tcl.h>

#include "internal.h"
#include "cmds.h"
#include "plugin.h"
#include "value.h"
#include "stringref.h"

struct tcl_signal_handler {
	Tcl_Obj *signal;
	Tcl_Interp *interp;

	void *instance;
	Tcl_Obj *namespace;
	/* These following two are temporary during setup */
	Tcl_Obj *args;
	Tcl_Obj *proc;

	PurpleValue *returntype;
	int nargs;
	PurpleValue **argtypes;
};

struct tcl_cmd_handler {
	int id;
	Tcl_Obj *cmd;
	Tcl_Interp *interp;

	Tcl_Obj *namespace;
	/* These are temporary during setup */
	const char *args;
	int priority;
	int flags;
	const char *prpl_id;
	Tcl_Obj *proc;
	const char *helpstr;

	int nargs;
};

extern PurplePlugin *_tcl_plugin;

/* Capitalized this way because these are "types" */
extern PurpleStringref *PurpleTclRefAccount;
extern PurpleStringref *PurpleTclRefConnection;
extern PurpleStringref *PurpleTclRefConversation;
extern PurpleStringref *PurpleTclRefPointer;
extern PurpleStringref *PurpleTclRefPlugin;
extern PurpleStringref *PurpleTclRefPresence;
extern PurpleStringref *PurpleTclRefStatus;
extern PurpleStringref *PurpleTclRefStatusAttr;
extern PurpleStringref *PurpleTclRefStatusType;
extern PurpleStringref *PurpleTclRefXfer;
extern PurpleStringref *PurpleTclRefHandle;

PurplePlugin *tcl_interp_get_plugin(Tcl_Interp *interp);

void tcl_signal_init(void);
void tcl_signal_handler_free(struct tcl_signal_handler *handler);
void tcl_signal_cleanup(Tcl_Interp *interp);
gboolean tcl_signal_connect(struct tcl_signal_handler *handler);
void tcl_signal_disconnect(void *instance, const char *signal, Tcl_Interp *interp);

void tcl_cmd_init(void);
void tcl_cmd_handler_free(struct tcl_cmd_handler *handler);
void tcl_cmd_cleanup(Tcl_Interp *interp);
PurpleCmdId tcl_cmd_register(struct tcl_cmd_handler *handler);
void tcl_cmd_unregister(PurpleCmdId id, Tcl_Interp *interp);

void purple_tcl_ref_init(void);
void *purple_tcl_ref_get(Tcl_Interp *interp, Tcl_Obj *obj, PurpleStringref *type);
Tcl_Obj *purple_tcl_ref_new(PurpleStringref *type, void *value);

Tcl_ObjCmdProc tcl_cmd_account;
Tcl_ObjCmdProc tcl_cmd_signal_connect;
Tcl_ObjCmdProc tcl_cmd_buddy;
Tcl_ObjCmdProc tcl_cmd_cmd;
Tcl_ObjCmdProc tcl_cmd_connection;
Tcl_ObjCmdProc tcl_cmd_conversation;
Tcl_ObjCmdProc tcl_cmd_core;
Tcl_ObjCmdProc tcl_cmd_debug;
Tcl_ObjCmdProc tcl_cmd_notify;
Tcl_ObjCmdProc tcl_cmd_plugins;
Tcl_ObjCmdProc tcl_cmd_prefs;
Tcl_ObjCmdProc tcl_cmd_presence;
Tcl_ObjCmdProc tcl_cmd_savedstatus;
Tcl_ObjCmdProc tcl_cmd_send_im;
Tcl_ObjCmdProc tcl_cmd_signal;
Tcl_ObjCmdProc tcl_cmd_status;
Tcl_ObjCmdProc tcl_cmd_status_attr;
Tcl_ObjCmdProc tcl_cmd_status_type;
Tcl_ObjCmdProc tcl_cmd_unload;

#endif /* _PURPLE_TCL_PURPLE_H_ */
