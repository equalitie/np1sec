/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2016, eQualit.ie
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

#ifndef SRC_PARTITION_H_
#define SRC_PARTITION_H_

#include <map>
#include <set>
#include <vector>

namespace np1sec
{

/*
 * Given a set of users that each want to kick a certain subset of the users
 * in the set, find the largest partition of the user set such that in each
 * part P of the partition, there is no subset Q of P such that everyone in Q
 * wants to kick everyone in P\Q.
 */

std::vector<std::set<std::string>> compute_conversation_partition(const std::map<std::string, const std::set<std::string>*>& kick_graph);

} // namespace np1sec

#endif
