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

#include "partition.h"

namespace np1sec
{

/*
 * Given a set of users that each want to kick a certain subset of the users
 * in the set, find the largest partition of the user set such that in each
 * part P of the partition, there is no subset Q of P such that everyone in Q
 * wants to kick everyone in P\Q.
 *
 * We implement this by taking the complement of the wants-to-kick graph
 * (the does-not-want-to-kick graph), and computing the strongly connected
 * components of that graph. Each SCC of the does-not-want-to-kick-graph
 * becomes one part of the partition of the user set.
 *
 * This is an implementation of Tarjan's strongly connected component
 * algorithm. Ideally, it would be linear in the number of edges of the
 * does-not-want-to-kick graph; but because the input is a wants-to-kick graph,
 * the algorithm ends up being O(n^2). More involved bookkeeping in Channel
 * could fix this.
 */

struct SccAlgorithm
{
	struct Node
	{
		std::string username;
		int index;
		int minimal_backpointer;
		bool on_stack;
	};
	
	SccAlgorithm(const std::map<std::string, const std::set<std::string>*>& complement_graph_):
		complement_graph(complement_graph_) {}
	
	std::vector<Node> nodes;
	const std::map<std::string, const std::set<std::string>*>& complement_graph;
	int free_index;
	std::vector<size_t> stack;
	std::vector<std::set<std::string>> components;
	
	void visit(size_t node_id);
};

void SccAlgorithm::visit(size_t node_id)
{
	const std::set<std::string>* edges_complement = complement_graph.at(nodes[node_id].username);
	
	nodes[node_id].index = free_index;
	nodes[node_id].minimal_backpointer = free_index;
	nodes[node_id].on_stack = true;
	free_index++;
	size_t stack_position = stack.size();
	stack.push_back(node_id);
	
	for (size_t i = 0; i < nodes.size(); i++) {
		if (i == node_id) {
			continue;
		}
		
		if (edges_complement->count(nodes[i].username)) {
			continue;
		}
		
		if (nodes[i].index == -1) {
			visit(i);
			if (nodes[node_id].minimal_backpointer > nodes[i].minimal_backpointer) {
				nodes[node_id].minimal_backpointer = nodes[i].minimal_backpointer;
			}
		} else if (nodes[i].on_stack) {
			if (nodes[node_id].minimal_backpointer > nodes[i].index) {
				nodes[node_id].minimal_backpointer = nodes[i].index;
			}
		}
	}
	
	if (nodes[node_id].minimal_backpointer == nodes[node_id].index) {
		std::set<std::string> component;
		while (stack.size() > stack_position) {
			size_t i = stack.back();
			stack.pop_back();
			nodes[i].on_stack = false;
			component.insert(nodes[i].username);
		}
		components.push_back(std::move(component));
	}
}

std::vector<std::set<std::string>> compute_channel_partition(const std::map<std::string, const std::set<std::string>*>& kick_graph)
{
	SccAlgorithm algorithm(kick_graph);
	for (const auto& i : kick_graph) {
		SccAlgorithm::Node node;
		node.username = i.first;
		node.index = -1;
		algorithm.nodes.push_back(node);
	}
	algorithm.free_index = 0;
	
	for (size_t i = 0; i < algorithm.nodes.size(); i++) {
		if (algorithm.nodes[i].index == -1) {
			algorithm.visit(i);
		}
	}
	
	return algorithm.components;
}

} // namespace np1sec
