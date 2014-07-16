/*
 *  Multiparty Off-the-Record Messaging library
 *  Copyright (C) 2014  eQualit.ie  
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 3 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __SESSION_H__
#define __SESSION_H__

#include "crypt.h"

class MessageDigest {
 public:
  HashBlock digest;
  unsigned long message_id;

  void update(std::string new_message)
  {    
    message_id = compute_message_id(new_message);
    digest = mpotr_hash(digest + new_message);
      
  };

  /**
     compute a  unique globally ordered id from the 
     time stamped message, ultimately this function
     should be overridable by the client
   */
  unsigned long compute_message_id(std::string cur_message);
};

/**
   This class is encapsulating all information and action, a user needs and performs in a session. 
 */
class MpotrSession {
protected:
  HashBlock _id;
  vector<SessionParticipant> peers; //keeps the list of the live participants in the room

  vector<SessionParticipant> peers_in_limbo; //keeps the list of the updated participants in the room once the join/accept or farewell finishes

  time key_freshness_time_stamp;
  
public:
  /* constructor, initiate by joining, equivalent to join
   or initiate in the spec*/
  MpotrSession();

  /**
     is called by the constructor if the room is already
     inhibited
   */
  join();

  /* should be called when someone new join the chatroom.
   this will modifies the session id*/
  accept();

  /**
     this will be called when a user leave a chatroom 
     to update the key
   */
  farewell();

  /** 
      When a user wants to send a message to a session
      it needs to call its send function
   */
  send();

  /**
     When a message is received from a session 
     the receive function needs to be called to decrypt
     
     it updates the session status

     @return the decrypted message to be shown, it might
     be null if the message was a meta message
   */
  receive();

  /* destructor, session should be destroyed at leave */
  ~MpotrSession();

};

#endif
