/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

#include "oscar.h"
#include "peer.h"

aim_module_t *aim__findmodulebygroup(OscarData *od, guint16 group)
{
	aim_module_t *cur;

	for (cur = (aim_module_t *)od->modlistv; cur; cur = cur->next) {
		if (cur->family == group)
			return cur;
	}

	return NULL;
}

aim_module_t *aim__findmodule(OscarData *od, const char *name)
{
	aim_module_t *cur;

	for (cur = (aim_module_t *)od->modlistv; cur; cur = cur->next) {
		if (strcmp(name, cur->name) == 0)
			return cur;
	}

	return NULL;
}

int aim__registermodule(OscarData *od, int (*modfirst)(OscarData *, aim_module_t *))
{
	aim_module_t *mod;

	if (!od || !modfirst)
		return -1;

	mod = g_new0(aim_module_t, 1);

	if (modfirst(od, mod) == -1) {
		g_free(mod);
		return -1;
	}

	if (aim__findmodule(od, mod->name)) {
		if (mod->shutdown)
			mod->shutdown(od, mod);
		g_free(mod);
		return -1;
	}

	mod->next = (aim_module_t *)od->modlistv;
	od->modlistv = mod;

	return 0;
}

void aim__shutdownmodules(OscarData *od)
{
	aim_module_t *cur;

	for (cur = (aim_module_t *)od->modlistv; cur; ) {
		aim_module_t *tmp;

		tmp = cur->next;

		if (cur->shutdown)
			cur->shutdown(od, cur);

		g_free(cur);

		cur = tmp;
	}

	od->modlistv = NULL;

	return;
}
