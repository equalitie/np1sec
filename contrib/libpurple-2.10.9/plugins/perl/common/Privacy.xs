#include "module.h"

MODULE = Purple::Privacy  PACKAGE = Purple::Privacy  PREFIX = purple_privacy_
PROTOTYPES: ENABLE

gboolean
purple_privacy_permit_add(account, name, local_only)
	Purple::Account account
	const char * name
	gboolean local_only

gboolean
purple_privacy_permit_remove(account, name, local_only)
	Purple::Account account
	const char * name
	gboolean local_only

gboolean
purple_privacy_deny_add(account, name, local_only)
	Purple::Account account
	const char * name
	gboolean local_only

gboolean
purple_privacy_deny_remove(account, name, local_only)
	Purple::Account account
	const char * name
	gboolean local_only

gboolean
purple_privacy_check(account, who)
	Purple::Account account
	const char * who
