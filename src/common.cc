
/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <string>

#include "commen.h"

void *
xmalloc(size_t size)
{
  void *result;

  log_assert(size < SIZE_T_CEILING);

  /* Some malloc() implementations return NULL when the input argument
     is zero. We don't bother detecting whether the implementation we're
     being compiled for does that, because it should hardly ever come up,
     and avoiding it unconditionally does no harm. */
  if (size == 0)
    size = 1;

  result = malloc(size);
  if (result == NULL)
    die_oom();

  return result;
}
