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

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

extern "C" {
  #include <assert.h>
}

#include <cstdint>
#include <sstream>
#include <iterator>
#include <stdexcept>
#include <vector>

#include "src/base64.h"

#define UNUSED(expr) (void)(expr)


enum np1secLoadFlag {
  NO_LOAD,
  NEW_EPHEMERAL_KEY,
  LEAVE,
  NEW_SECRET_SHARE
};

// The length of the output of the hash function in bytes.
const size_t c_hash_length = 32;

typedef uint8_t HashBlock[c_hash_length];
//typedef std::vector<uint8_t> SessionID;
typedef HashBlock SessionID;



#endif  // SRC_COMMON_H_
