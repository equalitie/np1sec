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

#ifndef SRC_SESSION_H_
#define SRC_SESSION_H_

#include <event2/event.h>

#include <map>
#include <string>
#include <vector>

#include "src/common.h"
#include "src/interface.h"
#include "src/participant.h"
#include "src/message.h"
#include "src/crypt.h"

class np1secSession;
class np1secUserState;

class MessageDigest {
 public:
  HashBlock digest;
  uint32_t message_id;

  void update(std::string new_message);

  /**
   * Compute a unique globally ordered id from the time stamped message,
   * ultimately this function should be overridable by the client.
   */
  uint32_t compute_message_id(std::string cur_message);
};


// Defining essential types
typedef uint8_t np1secBareMessage[];



/**
 * This class is encapsulating all information and action, a user needs and
 * performs in a session.
 */
class np1secSession {
 protected:
  Cryptic cryptic;
  HashBlock hashed_id;

  np1secUserState *us;
  std::string room_name;

  Participant myself;
  UnauthenticatedParticipantList participants_in_the_room;

  /**
   * Stores Transcript chain hashes indexed by message id
   */
  std::map<uint32_t, HashBlock*> transcript_chain;

  /**
   * Keeps the list of the live participants in the room and their current/new
   * keys/shares, last heartbeat, etc. The correct way of uisng this array is
   * participants[peers[i]]
   *
   * let change the name to peer_id
   * 
   * sorting of this list by LongTermId,peer_id is important because
   * it determines the order of the room which affect the session key
   * computation.
   */
  std::vector<std::string> peers;

  /**
   * Keeps the list of the updated participants in the room once the
   * join/accept or farewell finishes.
   */
  std::map<std::string,Participant> participants;

  /**
   * Keeps the list of the unauthenticated participants in the room before the
   * join/accept or farewell finishes.
   */
  std::map<std::string,Participant> unauthed_participants;

 /**
   * Insert new message hash into transcript chain
   *
   */
  void add_message_to_transcript(std::string message, uint32_t message_id);

  time_t key_freshness_time_stamp;

 /**
   * Generate acknowledgement timers for all other participants
   *
   */
  void start_ack_timers();

  /**
    * Construct and start timers for acking received messages
    *
    */
  void start_receive_ack_timer(std::string sender_id);

  /**
   * End ack timer on for given acknowledgeing participants
   *
   */
  void stop_timer_receive(std::string acknowledger_id);

  /*
   * Stop ack to send timers when user sends new message before timer expires
   *
   */
  void stop_timer_send();

 protected:
  SessionID session_id;
  np1secSession* my_parent = NULL;

  /**
   * it should be invoked only once to compute the session id
   * if one need session id then they need a new session
   *
   * @return return true upon successful computation
   */
  bool compute_session_id();

  /**
   * When someone join and authenticated, we should
   * tell all other joining users to stop joining the
   * sessions they are joining
   */
  void kill_my_sibling();

  /**
 * (n+1)sec sessions are implemented as finite state machines.
 * Each message transaction might ends up in state change. 
 * this is a generic class to store every state and manage its
 * transition, illigiblity etc
 * 
 */
  enum np1secSessionState {
    NONE,
    JOIN_REQUESTED,  // The thread has requested to join
                     // by sending ephemeral key
    REPLIED_TO_NEW_JOIN,  // The thread has received a join from a
                          // participant replied by participant list
    AUTHED_JOINER,  //This mean that the joiner is authed by the thread
                    //thread is waiting for more share to generate the key
                    //so no more join till t
    RE_SHARED,      // key is being made, thread has been sent its share,
                    // waiting for more shares. This is the same as
                    // AUTHED_JOINER but for leave procedure where there
                    // is no need to auth

    GROUP_KEY_GENERATED,  // The thread has computed the session
                          // key and has sent the conformation
    IN_SESSION,  // Key has been confirmed
    UPDATED_KEY,  // all new shares has been received and new
                  // key has been generated, no more send possible
    LEAVE_REQUESTED,  // Leave requested by the thread, waiting
                      // for final transcirpt consitancy check
    FAREWELLED,  // LEAVE is received from another participant and a
                 // meta message for transcript consistancy and
                 // new shares has been sent
    DEAD,  // Won't accept receive or sent messages, possibly throw up
    TOTAL_NO_OF_STATES //This should be always the last state
  };

  np1secSessionState my_state;

  /**
     list of state transitors:
     J: joining C: current

     J:
     in join

     receive accept (matching/nonmatching sid): -> Reply with auth to everybody on the list + (new) shares. set sid. add/replace/invalidate shares. 

     if ll shares received, reply with key conf
     move to to-be-confirmed. otherwise stay, join.

     receive conf (different sid): means somebody else confirmed first,
     auth to new user + new shares. update sid wait for missing shares.  end in join.

     C: 

     x: receive join 
     new session with sid, send a list of session users + Auth + shares
     end in accepting.

     accepting: receive auth, mark as authed. halt unauthed sibling sessions, send new accept (sid) + shares.

     receive accepting , update shares if all shares received move to-be-conf
     send confirm

     to-be-confirm -> receive conf, update conf list, all confirmed move to
     confirm. 
     received join: is wrong, join has no sid so it goes to current session.

  */
  
  /**
      For join user calls this when receivemessage has type of PARTICIPANTS_INFO

      sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender

      for everybody including the sender

      joiner should:
      - Authenticate sender if fail halt
      - compute session_id
      - add z_sender to the table of shares 
      - compute kc = kc_{joiner, everybody}
      - compute z_joiner
      - send 
      sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
   */
  np1secSessionState auth_and_reshare(np1secMessage received_message);

  /**
     For the joiner user, calls it when receive a session confirmation
     message.

     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), Hash(GroupKey, U_sender)
     
     of SESSION_CONFIRMATION type

     if it is the same sid as the session id, marks the confirmation in 
     the confirmation list for the sender. If all confirmed, change 
     state to IN_SESSION, call the call back join from ops.

     If the sid is different send a new join request

   */
  np1secSessionState confirm_or_resession(np1secMessage received_message);

  /**
     For the current user, calls it when receive join_request with
     
     (U_joiner, y_joiner)

     - start a new new participant list which does
     
     - computes session_id
     - new session does:
     - compute kc = kc_{joiner, everybody}
     - compute z_sender (self)
     - set new session status to REPLIED_TO_NEW_JOIN
     - send 

     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender
     
     of PARTICIPANT_INFO message type

     change status to REPLIED_TO_NEW_JOIN

   */
  np1secSessionState send_auth_share_and_participant_info(np1secMessage received_message);


  /**
     For the current user, calls it when receive PARTICIANT_INFO
     
      sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_sender

     -if the sender is the joiner, 
      - Authenticate joiner halt if fails
      - Change status to AUTHED_JOINER
      - Halt all sibling sessions

     - add z_sender to share table
     - if all share are there compute the group key send the confirmation
     
     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), Hash(GroupKey, U_sender)

       change status GROUP_KEY_GENERATED
     otherwise no change to the status

   */
  np1secSessionState confirm_auth_add_update_share_repo(np1secMessage received_message);
  

  /**
     For the current user, calls it when receive a session confirmation
     message.

     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), Hash(GroupKey, U_sender)

     if it is the same sid as the session id, marks the confirmation in 
     the confirmation list for the sender. If all confirmed, change 
     state to IN_SESSION, make this session the main session of the
     room

     If the sid is different, something is wrong halt drop session

  */
  np1secSessionState mark_confirm_and_may_move_session(np1secMessage received_message);

  /**
   * This will be called when another user leaves a chatroom to update the key.
   * 
   * This should send a message the same an empty meta message for sending
   * the leaving user the status of transcript consistency
   * 
   * This also make new session which send new share list for the shrinked session
   *
   * sid, ((U_1,y_i)...(U_{n-1},y_{n-1}), z_sender, transcript_consistency_stuff
   * 
   * Of FAREWELL type
   *
   * kills all sibling sessions in making as the leaving user is no longer 
   * available to confirm any new session.
   * 
   * The status of the session is changed to farewelled. 
   * The statatus of new sid session is changed to re_shared
   */
  np1secSessionState send_farewell_and_reshare(np1secMessage received_message);

  /**
     For the current/leaving user, calls it when receive FAREWELL
     
     sid, ((U_1,y_i)...(U_{n-1},y_{n-1}), z_sender, transcript_consistency_stuff

     -if sid matches, ask parent to run a routine transcript consistency check
     - if not, we are the leaving user just run a routine transcript consistency check
     - add z_sender to share table
     - if all share are there compute the group key send the confirmation
     
       sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), Hash(GroupKey, U_sender)

       change status GROUP_KEY_GENERATED
     otherwise no change to the status

   */
  np1secSessionState chcek_transcript_consistancy_update_share_repo(np1secMessage received_message);

  /**
     This pointer represent an edge in the transition
     graph of the session state machine.

     The state machine will be represented by a 
     double array index by State and Incoming Message
     type where each element np1secFSMGraphEdge object 
     is stored. This object says what action to
     to be taken and return the next state
     
  */
  typedef np1secSessionState (np1secSession::*np1secFSMGraphTransitionEdge) (np1secMessage received_message);

  np1secFSMGraphTransitionEdge np1secFSMGraphTransitionMatrix[np1secSession::TOTAL_NO_OF_STATES][np1secMessage::TOTAL_NO_OF_MESSAGE_TYPE] = {};

  /**
<<<<<<< HEAD
     Setups the state machine transition double array once and
     for all during the initiation.
  */
  void engrave_transition_graph()
  {
    //joining user
    np1secFSMGraphTransitionMatrix[JOIN_REQUESTED][np1secMessage::PARTICIPANTS_INFO] = auth_and_reshare;

    np1secFSMGraphTransitionMatrix[JOIN_REQUESTED][np1secMessage::SESSION_CONFIRMATION] = confirm_or_resession;

    //user currently in the session: current session
    np1secFSMGraphTransitionMatrix[IN_SESSION][np1secMessage::JOIN_REQUEST] = send_auth_share_and_participant_info;

    //new session for currently in previous session
    np1secFSMGraphTransitionMatrix[REPLIED_TO_NEW_JOIN][np1secMessage::PARTICIANT_INFO] = confirm_auth_add_update_share_repo;

    np1secFSMGraphTransitionMatrix[GROUP_KEY_GENERATED][np1secMessage::SESSION_CONFIRMATION] = mark_confirm_and_may_move_session;

    //Leave should have priority over join because the leaving user
    //is not gonna confirm the session and as such the join will
    //fail any way.

    //Therefore when leave is requested, 1. corresponding child sesion should
    //killall its sibling 2. No new child session should be created till
    //transition to the left session is complete

    np1secFSMGraphTransitionMatrix[IN_SESSION][np1secMessage::LEAVE_REQUEST] = send_farewell;

    np1secFSMGraphTransitionMatrix[RE_SHARED][np1secMessage::FAREWELL] = chcek_transcript_consistancy_update_share_repo;

    np1secFSMGraphTransitionMatrix[LEAVE_REQUESTED][np1secMessage::FAREWELL] = chcek_transcript_consistancy_update_share_repo

      //We don't accept join request while in farewelled state (for now at least)


  }
  
  /**
   * Received the pre-processed message and based on the state
   * of the session decides what is the appropriate action
   *
   * @param receive_message pre-processed received message handed in by receive function
   *
   * @return true if it was a valid message
   */
  bool state_handler(np1secMessage receivd_message)
  {
    if (np1secFSMGraphTransitionMatrix[my_state][received_message]) //other wise just ignore
      {
        my_state = np1secFSMGraphTransitionMatrix[my_state][received_message](received_message);
        return true
      }

    return false;
  }


  /**
=======
>>>>>>> master
    * Construct and start timers for sending heartbeat messages
    *
    */
  void start_heartbeat_timer();

  //This really doesn't make sense because we create a sessien based on
  //join request
  /**
   * Should be called by userstate when the user wants to join a new room
   *
   * @parma long_term_id_key the key pair of joining party is need for 
   *        deniable authentication
   *
   * @return return true if the first stage of join is completed successfully
   */
  bool join(LongTermIDKey long_term_id_key);

  /**
   * Insert the list of unauthenticated participants
   * based on the input received
   */
  bool received_p_list(std::string participant_list);

  /**
   * When a user wants to send a message to a session it needs to call its send
   * function.
   */
  bool send(std::string message, np1secMessage::np1secMessageType message_type);

 public:
  /**
     constructor
     You can't have a session without a user

     TODO:What about a session without a room?
   */
  np1secSession(np1secUserState *us);

  /**
   * Constructor, initiate by joining.
   */
  np1secSession(np1secUserState *us,
               std::string room_name,
               UnauthenticatedParticipantList participants_in_the_room);

  /**
   * access function for session_id;
   */
  SessionID my_session_id() { return session_id;}

  /**
   * When a message is received from a session the receive function needs to be
   * called to decrypt. It updates the session status and returns the decrypted
   * message to be shown, it might be null if the message was a meta message.
   */
  np1secMessage receive(std::string raw_message);

  /**
   * Destructor, session should be destroyed at leave.
   */
  ~np1secSession();
};

   /**
   * Callback function to manage sending of heartbeats
   *
   */
  static void cb_send_heartbeat(evutil_socket_t fd, short what, void *arg);

  /*
   * Callback function to cause automatic sending of ack for 
   * received message
   *
   */
  static void cb_send_ack(evutil_socket_t fd, short what, void *arg);

  /*
   * Callback function to cause automatic warning if ack not
   * received for previously sent message
   *
   */
  static void cb_ack_not_received(evutil_socket_t fd, short what, void *arg);

#endif  // SRC_SESSION_H_
