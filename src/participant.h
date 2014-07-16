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

#ifndef __PARTICIPANT_H__
#define __PARTICIPANT_H__
/** 
  This class keeps the state of each participant in the 
  room, including the user themselves
*/
class Participant
{
public:
  std:string id;
  MpotrPublicKey long_term_pub_key;
  MpotrPublicKey ephemeral_key;
  MessageDigest message_digest;

  MpotrKeyShare cur_keyshare;
  MpotrKeySHare future_key_share;

  enum ForwardSecracyContribution
  {
    NONE,
    EPHEMERAL,
    KEY_SHARE
  };
 
 ForwardSecracyContribution ForwardSecracyStatus;
 
};

#endif
