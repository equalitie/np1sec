#ifndef DBUS_API_SUBJECT_TO_CHANGE
#define DBUS_API_SUBJECT_TO_CHANGE
#endif

#include <stdio.h>
#include <stdlib.h>

#include "purple-client.h"

/*
   This example demonstrates how to use libpurple-client to communicate
   with purple.  The names and signatures of functions provided by
   libpurple-client are the same as those in purple.  However, all
   structures (such as PurpleAccount) are opaque, that is, you can only
   use pointer to them.  In fact, these pointers DO NOT actually point
   to anything, they are just integer identifiers of assigned to these
   structures by purple.  So NEVER try to dereference these pointers.
   Integer ids as disguised as pointers to provide type checking and
   prevent mistakes such as passing an id of PurpleAccount when an id of
   PurpleBuddy is expected.  According to glib manual, this technique is
   portable.
*/

int main (int argc, char **argv)
{
	GList *alist, *node;

	purple_init();

	alist = purple_accounts_get_all();
	for (node = alist; node != NULL; node = node->next)
	{
		PurpleAccount *account = (PurpleAccount*) node->data;
		char *name = purple_account_get_username(account);
		g_print("Name: %s\n", name);
		g_free(name);
	}
	g_list_free(alist);

	return 0;
}
