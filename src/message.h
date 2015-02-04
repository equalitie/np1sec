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

#ifndef SRC_MESSAGE_H_
#define SRC_MESSAGE_H_

class np1secMessage {
 protected:
  std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
  }


  std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
  }
  


 public:
  enum np1secMessageType {
    JOIN_REQUEST,
    PARTICIPANTS_INFO,
    GROUP_SHARE,
    USER_MESSAGE,
    PURE_META_MESSAG,
    LEAVE,
    FAREWELL
  };
  
  np1secMessageType message_type;
  std::string user_message;

  /**
   * @return if the message is of type PARTICIPANTS_INFO it returns 
   *         the list of participants with their ephemerals otherwise
   *         throw an exception
   */
  std::vector<UnauthenticatedParticipant> participants_in_the_room();
  
};

#endif  // SRC_MESSAGE_H_
