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

#include "src/participant.h"

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(Participant& lhs, Participant& rhs)
{

  return Cryptic::retrieve_result(lhs.long_term_pub_key) < Cryptic::retrieve_result(rhs.long_term_pub_key);

}

/**
 * Generate the approperiate authentication token check its equality
 * to authenticate the alleged participant
 *
 * @param auth_token authentication token received as a message
 * @param authenicator_id running thread user id  //TODO 
 *  can give it to youget rid of this as thread_user_as_partcipant 
 * @param thread_user_id_key the key (pub & prive) of the user running the 
 *        thread
 * 
 * @return true if peer's authenticity could be established
 */
bool Participant::be_authenticated(std::string authenticator_id, HashBlock auth_token, np1secAsymmetricKey thread_user_id_key) {
  if (!compute_p2p_private(thread_user_id_key))
    return false;
  
  std::string to_be_hashed(reinterpret_cast<const char*>(p2p_key), sizeof(HashBlock));
  to_be_hashed+= authenticator_id;
  HashBlock regenerated_auth_token;

  Cryptic::hash(to_be_hashed.c_str(), to_be_hashed.size(), regenerated_auth_token);

  return (!Cryptic::compare_hash(regenerated_auth_token, auth_token));

}

/**
 * Generate the approperiate authentication token check its equality
 * to authenticate the alleged participant
 *
 * @param auth_token authentication token received as a message
 * @param thread_user_id_key the key (pub & prive) of the user running the 
 *        thread
 * 
 * @return true if peer's authenticity could be established
 */
bool Participant::authenticate_to(HashBlock auth_token, np1secAsymmetricKey thread_user_id_key) {

  if (!compute_p2p_private(thread_user_id_key))
    return false;

  std::string to_be_hashed(reinterpret_cast<const char*>(p2p_key), sizeof(HashBlock));
  to_be_hashed+= id;
  Cryptic::hash(to_be_hashed.c_str(), to_be_hashed.size(), auth_token);

  return true;

}

/**
 * computes the p2p triple dh secret between participants
 *
 * @return true on success
 */
bool Participant::compute_p2p_private(np1secAsymmetricKey thread_user_id_key)
{
  thread_user_crypto->triple_ed_dh(ephemeral_key, long_term_pub_key, thread_user_id_key, sort_by_long_term_pub_key(*this, *thread_user_as_participant), &p2p_key);
                      
}
