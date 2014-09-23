/**
 * @file cmds.c Commands API
 * @ingroup core
 */

/* Copyright (C) 2003-2004 Timothy Ringenbach <omarvo@hotmail.com
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
 *
 */

#include "internal.h"

#include "account.h"
#include "util.h"
#include "cmds.h"

static GList *cmds = NULL;
static guint next_id = 1;

typedef struct _PurpleCmd {
	PurpleCmdId id;
	gchar *cmd;
	gchar *args;
	PurpleCmdPriority priority;
	PurpleCmdFlag flags;
	gchar *prpl_id;
	PurpleCmdFunc func;
	gchar *help;
	void *data;
} PurpleCmd;


static gint cmds_compare_func(const PurpleCmd *a, const PurpleCmd *b)
{
	if (a->priority > b->priority)
		return -1;
	else if (a->priority < b->priority)
		return 1;
	else return 0;
}

PurpleCmdId purple_cmd_register(const gchar *cmd, const gchar *args,
                            PurpleCmdPriority p, PurpleCmdFlag f,
                            const gchar *prpl_id, PurpleCmdFunc func,
                            const gchar *helpstr, void *data)
{
	PurpleCmdId id;
	PurpleCmd *c;

	g_return_val_if_fail(cmd != NULL && *cmd != '\0', 0);
	g_return_val_if_fail(args != NULL, 0);
	g_return_val_if_fail(func != NULL, 0);

	id = next_id++;

	c = g_new0(PurpleCmd, 1);
	c->id = id;
	c->cmd = g_strdup(cmd);
	c->args = g_strdup(args);
	c->priority = p;
	c->flags = f;
	c->prpl_id = g_strdup(prpl_id);
	c->func = func;
	c->help = g_strdup(helpstr);
	c->data = data;

	cmds = g_list_insert_sorted(cmds, c, (GCompareFunc)cmds_compare_func);

	purple_signal_emit(purple_cmds_get_handle(), "cmd-added", cmd, p, f);

	return id;
}

static void purple_cmd_free(PurpleCmd *c)
{
	g_free(c->cmd);
	g_free(c->args);
	g_free(c->prpl_id);
	g_free(c->help);
	g_free(c);
}

void purple_cmd_unregister(PurpleCmdId id)
{
	PurpleCmd *c;
	GList *l;

	for (l = cmds; l; l = l->next) {
		c = l->data;

		if (c->id == id) {
			cmds = g_list_remove(cmds, c);
			purple_signal_emit(purple_cmds_get_handle(), "cmd-removed", c->cmd);
			purple_cmd_free(c);
			return;
		}
	}
}

/**
 * This sets args to a NULL-terminated array of strings.  It should
 * be freed using g_strfreev().
 */
static gboolean purple_cmd_parse_args(PurpleCmd *cmd, const gchar *s, const gchar *m, gchar ***args)
{
	int i;
	const char *end, *cur;

	*args = g_new0(char *, strlen(cmd->args) + 1);

	cur = s;

	for (i = 0; cmd->args[i]; i++) {
		if (!*cur)
			return (cmd->flags & PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS);

		switch (cmd->args[i]) {
		case 'w':
			if (!(end = strchr(cur, ' '))) {
			  end = cur + strlen(cur);
			  (*args)[i] = g_strndup(cur, end - cur);
			  cur = end;
			} else {
			  (*args)[i] = g_strndup(cur, end - cur);
			  cur = end + 1;
			}
			break;
		case 'W':
		        if (!(end = strchr(cur, ' '))) {
			  end = cur + strlen(cur);
			  (*args)[i] = purple_markup_slice(m, g_utf8_pointer_to_offset(s, cur), g_utf8_pointer_to_offset(s, end));
			  cur = end;
			} else {
			  (*args)[i] = purple_markup_slice(m, g_utf8_pointer_to_offset(s, cur), g_utf8_pointer_to_offset(s, end));
			  cur = end +1;
			}
			break;
		case 's':
			(*args)[i] = g_strdup(cur);
			cur = cur + strlen(cur);
			break;
		case 'S':
			(*args)[i] = purple_markup_slice(m, g_utf8_pointer_to_offset(s, cur), g_utf8_strlen(cur, -1) + 1);
			cur = cur + strlen(cur);
			break;
		}
	}

	if (*cur)
		return (cmd->flags & PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS);

	return TRUE;
}

static void purple_cmd_strip_current_char(gunichar c, char *s, guint len)
{
	int bytes;

	bytes = g_unichar_to_utf8(c, NULL);
	memmove(s, s + bytes, len + 1 - bytes);
}

static void purple_cmd_strip_cmd_from_markup(char *markup)
{
	guint len = strlen(markup);
	char *s = markup;

	while (*s) {
		gunichar c = g_utf8_get_char(s);

		if (c == '<') {
			s = strchr(s, '>');
			if (!s)
				return;
		} else if (g_unichar_isspace(c)) {
			purple_cmd_strip_current_char(c, s, len - (s - markup));
			return;
		} else {
			purple_cmd_strip_current_char(c, s, len - (s - markup));
			continue;
		}
		s = g_utf8_next_char(s);
	}
}

PurpleCmdStatus purple_cmd_do_command(PurpleConversation *conv, const gchar *cmdline,
                                  const gchar *markup, gchar **error)
{
	PurpleCmd *c;
	GList *l;
	gchar *err = NULL;
	gboolean is_im;
	gboolean found = FALSE, tried_cmd = FALSE, right_type = FALSE, right_prpl = FALSE;
	const gchar *prpl_id;
	gchar **args = NULL;
	gchar *cmd, *rest, *mrest;
	PurpleCmdRet ret = PURPLE_CMD_RET_CONTINUE;

	*error = NULL;
	prpl_id = purple_account_get_protocol_id(purple_conversation_get_account(conv));

	if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM)
		is_im = TRUE;
	else if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT)
		is_im = FALSE;
	else
		return PURPLE_CMD_STATUS_FAILED;

	rest = strchr(cmdline, ' ');
	if (rest) {
		cmd = g_strndup(cmdline, rest - cmdline);
		rest++;
	} else {
		cmd = g_strdup(cmdline);
		rest = "";
	}

	mrest = g_strdup(markup);
	purple_cmd_strip_cmd_from_markup(mrest);

	for (l = cmds; l; l = l->next) {
		c = l->data;

		if (!purple_strequal(c->cmd, cmd))
			continue;

		found = TRUE;

		if (is_im)
			if (!(c->flags & PURPLE_CMD_FLAG_IM))
				continue;
		if (!is_im)
			if (!(c->flags & PURPLE_CMD_FLAG_CHAT))
				continue;

		right_type = TRUE;

		if ((c->flags & PURPLE_CMD_FLAG_PRPL_ONLY) &&
		    !purple_strequal(c->prpl_id, prpl_id))
			continue;

		right_prpl = TRUE;

		/* this checks the allow bad args flag for us */
		if (!purple_cmd_parse_args(c, rest, mrest, &args)) {
			g_strfreev(args);
			args = NULL;
			continue;
		}

		tried_cmd = TRUE;
		ret = c->func(conv, cmd, args, &err, c->data);
		if (ret == PURPLE_CMD_RET_CONTINUE) {
			g_free(err);
			err = NULL;
			g_strfreev(args);
			args = NULL;
			continue;
		} else {
			break;
		}

	}

	g_strfreev(args);
	g_free(cmd);
	g_free(mrest);

	if (!found)
		return PURPLE_CMD_STATUS_NOT_FOUND;

	if (!right_type)
		return PURPLE_CMD_STATUS_WRONG_TYPE;
	if (!right_prpl)
		return PURPLE_CMD_STATUS_WRONG_PRPL;
	if (!tried_cmd)
		return PURPLE_CMD_STATUS_WRONG_ARGS;

	if (ret == PURPLE_CMD_RET_OK) {
		return PURPLE_CMD_STATUS_OK;
	} else {
		*error = err;
		if (ret == PURPLE_CMD_RET_CONTINUE)
			return PURPLE_CMD_STATUS_NOT_FOUND;
		else
			return PURPLE_CMD_STATUS_FAILED;
	}

}


GList *purple_cmd_list(PurpleConversation *conv)
{
	GList *ret = NULL;
	PurpleCmd *c;
	GList *l;

	for (l = cmds; l; l = l->next) {
		c = l->data;

		if (conv && (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM))
			if (!(c->flags & PURPLE_CMD_FLAG_IM))
				continue;
		if (conv && (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT))
			if (!(c->flags & PURPLE_CMD_FLAG_CHAT))
				continue;

		if (conv && (c->flags & PURPLE_CMD_FLAG_PRPL_ONLY) &&
		    !purple_strequal(c->prpl_id, purple_account_get_protocol_id(purple_conversation_get_account(conv))))
			continue;

		ret = g_list_append(ret, c->cmd);
	}

	ret = g_list_sort(ret, (GCompareFunc)strcmp);

	return ret;
}


GList *purple_cmd_help(PurpleConversation *conv, const gchar *cmd)
{
	GList *ret = NULL;
	PurpleCmd *c;
	GList *l;

	for (l = cmds; l; l = l->next) {
		c = l->data;

		if (cmd && !purple_strequal(cmd, c->cmd))
			continue;

		if (conv && (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM))
			if (!(c->flags & PURPLE_CMD_FLAG_IM))
				continue;
		if (conv && (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT))
			if (!(c->flags & PURPLE_CMD_FLAG_CHAT))
				continue;

		if (conv && (c->flags & PURPLE_CMD_FLAG_PRPL_ONLY) &&
		    !purple_strequal(c->prpl_id, purple_account_get_protocol_id(purple_conversation_get_account(conv))))
			continue;

		ret = g_list_append(ret, c->help);
	}

	ret = g_list_sort(ret, (GCompareFunc)strcmp);

	return ret;
}

gpointer purple_cmds_get_handle(void)
{
	static int handle;
	return &handle;
}

void purple_cmds_init(void)
{
	gpointer handle = purple_cmds_get_handle();

	purple_signal_register(handle, "cmd-added",
			purple_marshal_VOID__POINTER_INT_INT, NULL, 3,
			purple_value_new(PURPLE_TYPE_STRING),
			purple_value_new(PURPLE_TYPE_INT),
			purple_value_new(PURPLE_TYPE_INT));
	purple_signal_register(handle, "cmd-removed",
			purple_marshal_VOID__POINTER, NULL, 1,
			purple_value_new(PURPLE_TYPE_STRING));
}

void purple_cmds_uninit(void)
{
	purple_signals_unregister_by_instance(purple_cmds_get_handle());
}

