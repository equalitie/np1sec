#include "conversation.h"

PurpleAccount *purple_accounts_find_ext(const char *name, const char *protocol_id,
				    gboolean (*account_test)(const PurpleAccount *account));

PurpleAccount *purple_accounts_find_any(const char *name, const char *protocol);

PurpleAccount *purple_accounts_find_connected(const char *name, const char *protocol);





