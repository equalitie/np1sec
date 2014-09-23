#include <string.h>
#include <glib.h>

#include "dbus-useful.h"
#include "conversation.h"
#include "util.h"


PurpleAccount *
purple_accounts_find_ext(const char *name, const char *protocol_id,
		       gboolean (*account_test)(const PurpleAccount *account))
{
	PurpleAccount *result = NULL;
	GList *l;
	char *who;

	if (name)
		who = g_strdup(purple_normalize(NULL, name));
	else
		who = NULL;

	for (l = purple_accounts_get_all(); l != NULL; l = l->next) {
		PurpleAccount *account = (PurpleAccount *)l->data;

		if (who && strcmp(purple_normalize(NULL, purple_account_get_username(account)), who))
			continue;

		if (protocol_id && strcmp(account->protocol_id, protocol_id))
			continue;

		if (account_test && !account_test(account))
			continue;

		result = account;
		break;
	}

	g_free(who);

	return result;
}

PurpleAccount *purple_accounts_find_any(const char *name, const char *protocol)
{
	return purple_accounts_find_ext(name, protocol, NULL);
}

PurpleAccount *purple_accounts_find_connected(const char *name, const char *protocol)
{
	return purple_accounts_find_ext(name, protocol, purple_account_is_connected);
}


