/**
 * @file tcl_signals.c Purple Tcl signal API
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
#include <tcl.h>
#include <stdarg.h>

#include "tcl_purple.h"

#include "internal.h"
#include "connection.h"
#include "conversation.h"
#include "signals.h"
#include "debug.h"
#include "value.h"
#include "core.h"

static GList *tcl_callbacks;

static void *tcl_signal_callback(va_list args, struct tcl_signal_handler *handler);
static Tcl_Obj *new_cb_namespace (void);

void tcl_signal_init()
{
	tcl_callbacks = NULL;
}

void tcl_signal_handler_free(struct tcl_signal_handler *handler)
{
	if (handler == NULL)
		return;

	Tcl_DecrRefCount(handler->signal);
	if (handler->namespace)
	{
		Tcl_DecrRefCount(handler->namespace);
	}
	g_free(handler);
}

void tcl_signal_cleanup(Tcl_Interp *interp)
{
	GList *cur;
	struct tcl_signal_handler *handler;

	for (cur = tcl_callbacks; cur != NULL; cur = g_list_next(cur)) {
		handler = cur->data;
		if (handler->interp == interp) {
			tcl_signal_handler_free(handler);
			cur->data = NULL;
		}
	}
	tcl_callbacks = g_list_remove_all(tcl_callbacks, NULL);
}

gboolean tcl_signal_connect(struct tcl_signal_handler *handler)
{
	GString *proc;

	purple_signal_get_values(handler->instance,
			       Tcl_GetString(handler->signal),
			       &handler->returntype, &handler->nargs,
			       &handler->argtypes);

	tcl_signal_disconnect(handler->interp, Tcl_GetString(handler->signal),
			      handler->interp);

	if (!purple_signal_connect_vargs(handler->instance,
				       Tcl_GetString(handler->signal),
				       (void *)handler->interp,
				       PURPLE_CALLBACK(tcl_signal_callback),
				       (void *)handler))
		return FALSE;

	handler->namespace = new_cb_namespace ();
	Tcl_IncrRefCount(handler->namespace);
	proc = g_string_new("");
	g_string_append_printf(proc, "namespace eval %s { proc cb { %s } { %s } }",
			       Tcl_GetString(handler->namespace),
			       Tcl_GetString(handler->args),
	                       Tcl_GetString(handler->proc));
	if (Tcl_Eval(handler->interp, proc->str) != TCL_OK) {
		Tcl_DecrRefCount(handler->namespace);
		g_string_free(proc, TRUE);
		return FALSE;
	}
	g_string_free(proc, TRUE);

	tcl_callbacks = g_list_append(tcl_callbacks, (gpointer)handler);

	return TRUE;
}

void tcl_signal_disconnect(void *instance, const char *signal, Tcl_Interp *interp)
{
	GList *cur;
	struct tcl_signal_handler *handler;
	gboolean found = FALSE;
	GString *cmd;

	for (cur = tcl_callbacks; cur != NULL; cur = g_list_next(cur)) {
		handler = cur->data;
		if (handler->interp == interp && handler->instance == instance
		    && !strcmp(signal, Tcl_GetString(handler->signal))) {
			purple_signal_disconnect(instance, signal, handler->interp,
					       PURPLE_CALLBACK(tcl_signal_callback));
			cmd = g_string_sized_new(64);
			g_string_printf(cmd, "namespace delete %s",
					Tcl_GetString(handler->namespace));
			Tcl_EvalEx(interp, cmd->str, -1, TCL_EVAL_GLOBAL);
			tcl_signal_handler_free(handler);
			g_string_free(cmd, TRUE);
			cur->data = NULL;
			found = TRUE;
			break;
		}
	}
	if (found)
		tcl_callbacks = g_list_remove_all(tcl_callbacks, NULL);
}

static PurpleStringref *ref_type(PurpleSubType type)
{
	switch (type) {
	case PURPLE_SUBTYPE_ACCOUNT:
		return PurpleTclRefAccount;
	case PURPLE_SUBTYPE_CONNECTION:
		return PurpleTclRefConnection;
	case PURPLE_SUBTYPE_CONVERSATION:
		return PurpleTclRefConversation;
	case PURPLE_SUBTYPE_PLUGIN:
		return PurpleTclRefPlugin;
	case PURPLE_SUBTYPE_STATUS:
		return PurpleTclRefStatus;
	case PURPLE_SUBTYPE_XFER:
		return PurpleTclRefXfer;
	default:
		return NULL;
	}
}

static void *tcl_signal_callback(va_list args, struct tcl_signal_handler *handler)
{
	GString *name, *val;
	PurpleBlistNode *node;
	int i;
	void *retval = NULL;
	Tcl_Obj *cmd, *arg, *result;
	void **vals; /* Used for inout parameters */
	char ***strs;

	vals = g_new0(void *, handler->nargs);
	strs = g_new0(char **, handler->nargs);
	name = g_string_sized_new(32);
	val = g_string_sized_new(32);

	cmd = Tcl_NewListObj(0, NULL);
	Tcl_IncrRefCount(cmd);

	arg = Tcl_DuplicateObj(handler->namespace);
	Tcl_AppendStringsToObj(arg, "::cb", NULL);
	Tcl_ListObjAppendElement(handler->interp, cmd, arg);

	for (i = 0; i < handler->nargs; i++) {
		if (purple_value_is_outgoing(handler->argtypes[i]))
			g_string_printf(name, "%s::arg%d",
					Tcl_GetString(handler->namespace), i);

		switch(purple_value_get_type(handler->argtypes[i])) {
		case PURPLE_TYPE_UNKNOWN:	/* What?  I guess just pass the word ... */
			/* treat this as a pointer, but complain first */
			purple_debug(PURPLE_DEBUG_ERROR, "tcl", "unknown PurpleValue type %d\n",
				   purple_value_get_type(handler->argtypes[i]));
		case PURPLE_TYPE_POINTER:
		case PURPLE_TYPE_OBJECT:
		case PURPLE_TYPE_BOXED:
			/* These are all "pointer" types to us */
			if (purple_value_is_outgoing(handler->argtypes[i]))
				purple_debug_error("tcl", "pointer types do not currently support outgoing arguments\n");
			arg = purple_tcl_ref_new(PurpleTclRefPointer, va_arg(args, void *));
			break;
		case PURPLE_TYPE_BOOLEAN:
			if (purple_value_is_outgoing(handler->argtypes[i])) {
				vals[i] = va_arg(args, gboolean *);
				Tcl_LinkVar(handler->interp, name->str,
					    (char *)&vals[i], TCL_LINK_BOOLEAN);
				arg = Tcl_NewStringObj(name->str, -1);
			} else {
				arg = Tcl_NewBooleanObj(va_arg(args, gboolean));
			}
			break;
		case PURPLE_TYPE_CHAR:
		case PURPLE_TYPE_UCHAR:
		case PURPLE_TYPE_SHORT:
		case PURPLE_TYPE_USHORT:
		case PURPLE_TYPE_INT:
		case PURPLE_TYPE_UINT:
		case PURPLE_TYPE_LONG:
		case PURPLE_TYPE_ULONG:
		case PURPLE_TYPE_ENUM:
			/* I should really cast these individually to
			 * preserve as much information as possible ...
			 * but heh */
			if (purple_value_is_outgoing(handler->argtypes[i])) {
				vals[i] = va_arg(args, int *);
				Tcl_LinkVar(handler->interp, name->str,
					    vals[i], TCL_LINK_INT);
				arg = Tcl_NewStringObj(name->str, -1);
			} else {
				arg = Tcl_NewIntObj(va_arg(args, int));
			}
			break;
		case PURPLE_TYPE_INT64:
		case PURPLE_TYPE_UINT64:
			/* Tcl < 8.4 doesn't have wide ints, so we have ugly
			 * ifdefs in here */
			if (purple_value_is_outgoing(handler->argtypes[i])) {
				vals[i] = (void *)va_arg(args, gint64 *);
				#if (TCL_MAJOR_VERSION >= 8 && TCL_MINOR_VERSION >= 4)
				Tcl_LinkVar(handler->interp, name->str,
					    vals[i], TCL_LINK_WIDE_INT);
				#else
				/* This is going to cause weirdness at best,
				 * but what do you want ... we're losing
				 * precision */
				Tcl_LinkVar(handler->interp, name->str,
					    vals[i], TCL_LINK_INT);
				#endif /* Tcl >= 8.4 */
				arg = Tcl_NewStringObj(name->str, -1);
			} else {
				#if (TCL_MAJOR_VERSION >= 8 && TCL_MINOR_VERSION >= 4)
				arg = Tcl_NewWideIntObj(va_arg(args, gint64));
				#else
				arg = Tcl_NewIntObj((int)va_arg(args, int));
				#endif /* Tcl >= 8.4 */
			}
			break;
		case PURPLE_TYPE_STRING:
			if (purple_value_is_outgoing(handler->argtypes[i])) {
				strs[i] = va_arg(args, char **);
				if (strs[i] == NULL || *strs[i] == NULL) {
					vals[i] = ckalloc(1);
					*(char *)vals[i] = '\0';
				} else {
					size_t len = strlen(*strs[i]) + 1;
					vals[i] = ckalloc(len);
					g_strlcpy(vals[i], *strs[i], len);
				}
				Tcl_LinkVar(handler->interp, name->str,
					    (char *)&vals[i], TCL_LINK_STRING);
				arg = Tcl_NewStringObj(name->str, -1);
			} else {
				arg = Tcl_NewStringObj(va_arg(args, char *), -1);
			}
			break;
		case PURPLE_TYPE_SUBTYPE:
			switch (purple_value_get_subtype(handler->argtypes[i])) {
			case PURPLE_SUBTYPE_UNKNOWN:
				purple_debug(PURPLE_DEBUG_ERROR, "tcl", "subtype unknown\n");
			case PURPLE_SUBTYPE_ACCOUNT:
			case PURPLE_SUBTYPE_CONNECTION:
			case PURPLE_SUBTYPE_CONVERSATION:
			case PURPLE_SUBTYPE_STATUS:
			case PURPLE_SUBTYPE_PLUGIN:
			case PURPLE_SUBTYPE_XFER:
				if (purple_value_is_outgoing(handler->argtypes[i]))
					purple_debug_error("tcl", "pointer subtypes do not currently support outgoing arguments\n");
				arg = purple_tcl_ref_new(ref_type(purple_value_get_subtype(handler->argtypes[i])), va_arg(args, void *));
				break;
			case PURPLE_SUBTYPE_BLIST:
			case PURPLE_SUBTYPE_BLIST_BUDDY:
			case PURPLE_SUBTYPE_BLIST_GROUP:
			case PURPLE_SUBTYPE_BLIST_CHAT:
				/* We're going to switch again for code-deduping */
				if (purple_value_is_outgoing(handler->argtypes[i]))
					node = *va_arg(args, PurpleBlistNode **);
				else
					node = va_arg(args, PurpleBlistNode *);
				switch (purple_blist_node_get_type(node)) {
				case PURPLE_BLIST_GROUP_NODE:
					arg = Tcl_NewListObj(0, NULL);
					Tcl_ListObjAppendElement(handler->interp, arg,
								 Tcl_NewStringObj("group", -1));
					Tcl_ListObjAppendElement(handler->interp, arg,
								 Tcl_NewStringObj(purple_group_get_name((PurpleGroup *)node), -1));
					break;
				case PURPLE_BLIST_CONTACT_NODE:
					/* g_string_printf(val, "contact {%s}", Contact Name? ); */
					arg = Tcl_NewStringObj("contact", -1);
					break;
				case PURPLE_BLIST_BUDDY_NODE:
					arg = Tcl_NewListObj(0, NULL);
					Tcl_ListObjAppendElement(handler->interp, arg,
								 Tcl_NewStringObj("buddy", -1));
					Tcl_ListObjAppendElement(handler->interp, arg,
								 Tcl_NewStringObj(purple_buddy_get_name((PurpleBuddy *)node), -1));
					Tcl_ListObjAppendElement(handler->interp, arg,
								 purple_tcl_ref_new(PurpleTclRefAccount,
										    purple_buddy_get_account((PurpleBuddy *)node)));
					break;
				case PURPLE_BLIST_CHAT_NODE:
					arg = Tcl_NewListObj(0, NULL);
					Tcl_ListObjAppendElement(handler->interp, arg,
								 Tcl_NewStringObj("chat", -1));
					Tcl_ListObjAppendElement(handler->interp, arg,
								 Tcl_NewStringObj(purple_chat_get_name((PurpleChat *)node), -1));
					Tcl_ListObjAppendElement(handler->interp, arg,
								 purple_tcl_ref_new(PurpleTclRefAccount,
										  purple_chat_get_account((PurpleChat *)node)));
					break;
				case PURPLE_BLIST_OTHER_NODE:
					arg = Tcl_NewStringObj("other", -1);
					break;
				}
				break;
			}
		}
		Tcl_ListObjAppendElement(handler->interp, cmd, arg);
	}

	/* Call the friggin' procedure already */
	if (Tcl_EvalObjEx(handler->interp, cmd, TCL_EVAL_GLOBAL) != TCL_OK) {
		purple_debug(PURPLE_DEBUG_ERROR, "tcl", "error evaluating callback: %s\n",
			   Tcl_GetString(Tcl_GetObjResult(handler->interp)));
	} else {
		result = Tcl_GetObjResult(handler->interp);
		/* handle return values -- strings and words only */
		if (handler->returntype) {
			if (purple_value_get_type(handler->returntype) == PURPLE_TYPE_STRING) {
				retval = (void *)g_strdup(Tcl_GetString(result));
			} else {
				if (Tcl_GetIntFromObj(handler->interp, result, (int *)&retval) != TCL_OK) {
					purple_debug(PURPLE_DEBUG_ERROR, "tcl", "Error retrieving procedure result: %s\n",
						   Tcl_GetString(Tcl_GetObjResult(handler->interp)));
					retval = NULL;
				}
			}
		}
	}

	/* And finally clean up */
	for (i = 0; i < handler->nargs; i++) {
		g_string_printf(name, "%s::arg%d",
				Tcl_GetString(handler->namespace), i);
		if (purple_value_is_outgoing(handler->argtypes[i])
		    && purple_value_get_type(handler->argtypes[i]) != PURPLE_TYPE_SUBTYPE)
			Tcl_UnlinkVar(handler->interp, name->str);

		/* We basically only have to deal with strings on the
		 * way out */
		switch (purple_value_get_type(handler->argtypes[i])) {
		case PURPLE_TYPE_STRING:
			if (purple_value_is_outgoing(handler->argtypes[i])) {
				if (vals[i] != NULL && *(char **)vals[i] != NULL) {
					g_free(*strs[i]);
					*strs[i] = g_strdup(vals[i]);
				}
				ckfree(vals[i]);
			}
			break;
		default:
			/* nothing */
			;
		}
	}

	g_string_free(name, TRUE);
	g_string_free(val, TRUE);
	g_free(vals);
	g_free(strs);

	return retval;
}

static Tcl_Obj *new_cb_namespace ()
{
	static int cbnum;
	char name[32];

	g_snprintf (name, sizeof(name), "::purple::_callback::cb_%d", cbnum++);
	return Tcl_NewStringObj (name, -1);
}
