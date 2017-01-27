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

#ifndef SRC_DEBUG_H_
#define SRC_DEBUG_H_

#include <ostream>
#include "message.h"
#include "bytearray.h"

namespace np1sec {
	template<class R> struct Range {
		const R& inner;
	};

	template<class R> Range<R> range(const R& inner) {
		return Range<R>{inner};
	}
} // namespace np1sec

template<class R>
std::ostream& operator<<(std::ostream& os, const np1sec::Range<R>& r)
{
	auto& range = r.inner;

	os << "[";
	for (auto i = range.begin(); i != range.end(); ++i) {
		if (i != range.begin()) os << ", ";
		os << *i;
	}
	return os << "]";
}

template<int N>
std::ostream& operator<<(std::ostream& os, const np1sec::ByteArray<N>& ba)
{
	return os << ba.dump_hex().substr(0, 8);
}

std::ostream& operator<<(std::ostream&, np1sec::Message::Type);
std::ostream& operator<<(std::ostream&, const np1sec::Message&);

#endif


