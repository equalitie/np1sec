/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 *  License as published by the Free Software Foundation.
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
#include <utility>
#include <algorithm>

#include "src/common.h"
#include "src/interface.h"
#include "src/participant.h"
#include "src/message.h"
#include "src/crypt.h"

class np1secUserState;
class np1secSession;

/**
 * Callback function to manage sending of heartbeats
 *
 */
static void cb_send_heartbeat(evutil_socket_t fd, short what, void *arg);

/**
 * Callback function to cause automatic sending of ack for 
 * received message
 *
 */
static void cb_send_ack(evutil_socket_t fd, short what, void *arg);

/**
 * Callback function to cause automatic warning if ack not
 * received for previously sent message
 *
 */
static void cb_ack_not_received(evutil_socket_t fd, short what, void *arg);

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

//This has been removed in favor of np1secSession::operator- function
//np1secSession::operator+ functions.
//which compute the contrast of two sessions and gives set up of joining
//and leaving users.
/* /\** */
/*  * it represents a message from a session to the room. When a room needs */
/*  * to take action based on result of a message that a session is received */
/*  * */
/*  *  */
/*  * */
/*  *\/ */
class RoomAction { 
   //historically RoomAction was the way to inform chat client about */
   //actions, however we decided the main tool for action transmission */
   //to chat client are callback function */

   // the only real action type is only */
   //activate which signal changing active session and hence */
   //cryptographically verifiable join and leave. */
  public: 
   enum ActionType { 
     NO_ACTION,
     BAD_ACTION,
     NEW_SESSION,
/*     JOIN, */
/*     LEAVE, */
/*     REKEY, */
/*     NEW_MESSAGE */
   }; 

   ActionType action_type;
   UnauthenticatedParticipant acting_user;  // The user which joined, left or sent a message. */
   np1secSession* bred_session = nullptr;

 RoomAction(ActionType action = NO_ACTION, std::string  acting_user_nick = "")
   : action_type(action),
     acting_user(acting_user_nick)
   {}
   
};

const RoomAction c_no_room_action;

/**
 * reason of the creation of the session. it can be
 * JOIN, LEAVE or RESESSION.
 * 
 * A bred session will be dead:
 *   - if the activated session satisfies its raison d'etre.
 *   - if the bred session defies its rasion d'etre
 */
struct RaisonDEtre {
  enum ReasonType {
    JOIN,
    LEAVE,
    RESESSION
  };

  ParticipantId changing_particpant;

};

// Defining essential types
typedef uint8_t np1secBareMessage[];
typedef std::map<std::string,Participant> ParticipantMap;

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

  //TODO: To keep track of why the session is created and if it is
  //still relevant
  std::list<RaisonDEtre> raisons_detre;

  ParticipantId myself; //to keep the nickname and the long term id key
  //these are necessary to send join request 
  size_t my_index;
  /**
   * Keeps the list of the unauthenticated participants in the room before the
   * join/accept or farewell finishes.
   */
  //TODO:: this is redundent now. We should get rid of it and stick with
  //participant map.
  //UnauthenticatedParticipantList participants_in_the_room;

  /**
   * Stores Transcritp chain hashes indexed by message id
   */
  std::map<uint32_t, HashBlock*> transcript_chain;

  //participants data:
  /**
   * Keeps the list of the updated participants in the room once the
   * join/accept or farewell finishes.
   */
  ParticipantMap participants;

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
   * Checkoff confirmed participant indexed by participant index
   * this information is not stored in the participant object
   * as:
   *  1. Very short term needed, only before the establishement of the session. 
   *  (in contrast to heart beat timer for e.g.)
   *  2. Is no longer valid for subsequent sessions. (new session need new confirmation). (In contrast to authenticated for e.g.)
   *  
   */
  std::vector<bool> confirmed_peers;

  /**
   * Keeps the list of the unauthenticated participants in the room before the
   * join/accept or farewell finishes.
   */
  //std::map<std::string,Participant> unauthed_participants; 

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
  SessionId session_id;
  HashBlock session_key_secret_share;
  HashBlock session_key;
  HashBlock session_confirmation;
  //Depricated in favor of raison detr.
  //tree structure seems to be insufficient. because
  //sid only encode the session structure but not
  //why sid is generated it could be generated for
  //two different reasons, though I can't come
  // up with an example.

  //keeping track of tree
  //np1secSession* my_parent = nullptr; 
  /* /\** */
  /*  * When someone join and authenticated, we should */
  /*  * tell all other joining users to stop joining the */
  /*  * sessions they are joining */
  /*  *\/ */
  /* void kill_my_sibling(); */

  /* /\** */
  /*  * When someone join and authenticated, we should */
  /*  * tell all other joining users to stop joining the */
  /*  * other sessions, the request for killing session */
  /*  * rival session coming from the nticated */
  /*  * child session */
  /*  *\/ */
  /* void kill_rival_children(); */


  /**
   * reading the particpant_in_the_room list, it populate the 
   * particpants
   * reading the particpant map, it populate the 
   * peers vector then find the index of thread runner
   */
  void populate_participants_and_peers(UnauthenticatedParticipantList session_view)
  {
    for(UnauthenticatedParticipantList::iterator view_it = session_view.begin(); view_it != session_view.end();  view_it++) {
      participants.insert(std::pair<std::string, Participant>(view_it->participant_id.nickname, Participant(*view_it, &cryptic)));
      peers.push_back(view_it->participant_id.nickname);
    
    }

    keep_peers_in_order_spot_myself();

  }

  void populate_peers_from_participants()
  {
    peers.clear();
    for(ParticipantMap::iterator it = participants.begin(); it != participants.end();  it++) {
      peers.push_back(it->first);
    }

    keep_peers_in_order_spot_myself();

  }

  /**
   * generate a session view by iterating over session_view
   */
  UnauthenticatedParticipantList session_view()
  {
    UnauthenticatedParticipantList session_view;
    for(size_t i = 0; i <  peers.size(); i++) {
      session_view.push_back(UnauthenticatedParticipant(participants[peers[i]].id, Cryptic::hash_to_string_buff(participants[peers[i]].raw_ephemeral_key),participants[peers[i]].authenticated));
    }
    
    return session_view;
    
  }

  /**
   * everytime that peers are modified we need to call this function to 
   * to keep it in order
   */
  void keep_peers_in_order_spot_myself()
  {

    std::sort(peers.begin(), peers.end());
    
    std::vector<std::string>::iterator my_entry = std::find(peers.begin(), peers.end(), myself.nickname);
    if (my_entry == peers.end())
      assert(0); //throw up

    my_index = std::distance(peers.begin(), my_entry);

    for(size_t i = 0; i <  peers.size(); i++)
      participants[peers[i]].index = i;
    
  }


// TODO: This should move to crypto really and called hash with
// overloaded parameters
  gcry_error_t compute_hash(uint8_t*, std::string);
  
  /**
   * it should be invoked only once to compute the session id
   * if one need session id then they need a new session
   *
   * @return return true upon successful computation
   */
  bool compute_session_id();
  bool compute_session_confirmation();
  bool validate_session_confirmation(np1secMessage confirmation_message);

  bool setup_session_view(np1secMessage session_view_message);

  bool group_enc();
  bool group_dec();

  gcry_error_t compute_message_hash(HashBlock transcript_chain,
                                  std::string message);

  /**
   * Simply checks the confirmed array for every element be true
   */
  bool everybody_confirmed();

  /**
   * Simply checks the participant map  for every element be authed.
   */
  bool everybody_authenticated_and_contributed();

  //Messaging functions
  /**
  * When session changes with no need to inform
  * new people about it (leave) then this function is 
  * is used (no participant_info)
  */
  bool send_auth_and_share_message();

  /**
   *   Joiner call this after receiving the participant info to
   *    authenticate to everybody in the room
   */
  bool joiner_send_auth_and_share();
  
  /**
     Preparinig PARTICIPANT_INFO Message

     current user calls this to send participant info to joiner
     and others
     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
  */
  bool send_view_auth_and_share(std::string joiner_id = "");

  public:
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
    SCHEDULED_TO_DIE, //a new session has been activated,
    //we receive all messages which has been sent before arrival of
    //last confirmation
    TOTAL_NO_OF_STATES //This should be always the last state
  };

  protected:
  np1secSessionState my_state;
  typedef std::pair<np1secSessionState, RoomAction> StateAndAction;

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
  StateAndAction auth_and_reshare(np1secMessage received_message);

  /**
     For the joiner user, calls it when receive a session confirmation
     message.

     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), hash(GroupKey, U_sender)
     
     of SESSION_CONFIRMATION type

     if it is the same sid as the session id, marks the confirmation in 
     the confirmation list for the sender. If all confirmed, change 
     state to IN_SESSION, call the call back join from ops.

     If the sid is different send a new join request

   */
  StateAndAction confirm_or_resession(np1secMessage received_message);

  /**
     For the current user, calls it when receive JOIN_REQUEST with
     
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
  StateAndAction send_auth_share_and_participant_info(np1secMessage received_message);

  /**
     For the current user, calls it when receive JOINER_AUTH
     
      sid, kc, z_sender

      - Authenticate joiner halt if fails
      - Change status to AUTHED_JOINER
      - Halt all sibling sessions

     - add z_sender to share table
     - if all share are there compute the group key send the confirmation
     
     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), hash(GroupKey, U_sender)

       change status GROUP_KEY_GENERATED
     otherwise no change to the status

   */
  StateAndAction confirm_auth_add_update_share_repo(np1secMessage received_message);
    
  /**
     For the current user, calls it when receive a session confirmation
     message.

     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), hash(GroupKey, U_sender)

     if it is the same sid as the session id, marks the confirmation in 
     the confirmation list for the sender. If all confirmed, change 
     state to IN_SESSION, make this session the main session of the
     room

     If the sid is different, something is wrong halt drop session

  */
  StateAndAction mark_confirmed_and_may_move_session(np1secMessage received_message);

  /**
   * This will be called when another user leaves a chatroom to update the key.
   * 
   * This should send a message the same an empty meta message for sending
   * the leaving user the status of transcript consistency
   * 
   * This also make new session which send message of Of FAREWELL type new
   * share list for the shrinked session 
   *
   * sid, ((U_1,y_i)...(U_{n-1},y_{n-1}), z_sender, transcript_consistency_stuff
   *
   * kills all sibling sessions in making as the leaving user is no longer 
   * available to confirm any new session.
   * 
   * The status of the session is changed to farewelled. 
   * The statatus of new sid session is changed to re_shared
   */
  StateAndAction send_farewell_and_reshare(np1secMessage received_message);

  /**
     For the current/leaving user, calls it when receive FAREWELL
     
     sid, ((U_1,y_i)...(U_{n-1},y_{n-1}), z_sender, transcript_consistency_stuff

     -if sid matches, ask parent to run a routine transcript consistency check
     - if not, we are the leaving user just run a routine transcript consistency check
     - add z_sender to share table
     - if all share are there compute the group key send the confirmation
     
       sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), hash(GroupKey, U_sender)

       change status GROUP_KEY_GENERATED
     otherwise no change to the status

   */
  StateAndAction check_transcript_consistancy_update_share_repo(np1secMessage received_message);

  /**
     This pointer represent an edge in the transition
     graph of the session state machine.

     The state machine will be represented by a 
     double array index by State and Incoming Message
     type where each element np1secFSMGraphEdge object 
     is stored. This object says what action to
     to be taken and return the next state
     
  */
  typedef StateAndAction (np1secSession::*np1secFSMGraphTransitionEdge) (np1secMessage received_message);

  np1secFSMGraphTransitionEdge np1secFSMGraphTransitionMatrix[np1secSession::TOTAL_NO_OF_STATES][np1secMessage::TOTAL_NO_OF_MESSAGE_TYPE] = {};

  /**
     Setups the state machine transition double array once and
     for all during the initiation.
  */
  void engrave_transition_graph()
  {
    //joining user
    np1secFSMGraphTransitionMatrix[JOIN_REQUESTED][np1secMessage::PARTICIPANTS_INFO] = &np1secSession::auth_and_reshare;

    np1secFSMGraphTransitionMatrix[JOIN_REQUESTED][np1secMessage::SESSION_CONFIRMATION] = &np1secSession::confirm_or_resession;

    //user currently in the session: current session
    np1secFSMGraphTransitionMatrix[IN_SESSION][np1secMessage::JOIN_REQUEST] = &np1secSession::send_auth_share_and_participant_info;

    //new session for currently in previous session
    np1secFSMGraphTransitionMatrix[REPLIED_TO_NEW_JOIN][np1secMessage::PARTICIPANTS_INFO] = &np1secSession::confirm_auth_add_update_share_repo;

    np1secFSMGraphTransitionMatrix[GROUP_KEY_GENERATED][np1secMessage::SESSION_CONFIRMATION] = &np1secSession::mark_confirmed_and_may_move_session;

    //Leave should have priority over join because the leaving user
    //is not gonna confirm the session and as such the join will
    //fail any way.

    //Therefore when leave is requested, 1. corresponding child sesion should
    //killall its sibling 2. No new child session should be created till
    //transition to the left session is complete

    //LEAVE Request is indicated in the meta message of user message
    //np1secFSMGraphTransitionMatrix[IN_SESSION][np1secMessage::LEAVE_REQUEST] = &np1secSession::send_farewell_and_reshare;

    np1secFSMGraphTransitionMatrix[RE_SHARED][np1secMessage::FAREWELL] = &np1secSession::check_transcript_consistancy_update_share_repo;

    np1secFSMGraphTransitionMatrix[LEAVE_REQUESTED][np1secMessage::FAREWELL] = &np1secSession::check_transcript_consistancy_update_share_repo;

    //We don't accept join request while in farewelled state (for now at least)
    //TODO: we should forward it with the session with reduced plist.

  }

  /**
    * Construct and start timers for sending heartbeat messages
    *
    */
  void start_heartbeat_timer();

  //This really doesn't make sense because we create a sessien based on
  //join request
  /* /\** */
  /*  * Should be called by userstate when the user wants to join a new room */
  /*  * */
  /*  * @parma long_term_id_key the key pair of joining party is need for  */
  /*  *        deniable authentication */
  /*  * */
  /*  * @return return true if the first stage of join is completed successfully */
  /*  *\/ */
  /* bool join(LongTermIDKey long_term_id_key); */

  /**
   * Insert the list of unauthenticated participants
   * based on the input received
   */
  bool received_p_list(std::string participant_list);

 public:
  /**
   * access function for state
   */
  np1secSessionState get_state() {return my_state;}
  
  /**
   * Received the pre-processed message and based on the state
   * of the session decides what is the appropriate action
   *
   * @param receive_message pre-processed received message handed in by receive function
   *
   * @return the external action which need to be taken over the room
   *         states of other session, user state etc. This is the 
   *         main way
   */
  RoomAction state_handler(np1secMessage receivd_message);

  /**
   * change the state to DEAD. it is needed when we bread a new
   * session out of this session.
   */
  void commit_suicide() { my_state = DEAD; };

  /**
   * Create a new np1secSession object based on the combination of participants
   * from the current session plus another session
   *
   */
  np1secSession operator+(np1secSession a);

  /**
   * Create a new np1secSession object based which has all the participants
   * from the current session minus the provided session
   *
   */
  np1secSession operator-(np1secSession a);

  /**
   * When a user wants to send a message to a session it needs to call its send
   * function.
   */
  bool send(std::string message, np1secMessage::np1secMessageType message_type);

  //List of constructors
  /* /\** */
  /*    constructor */
  /*    You can't have a session without a user */

  /*    TODO:What about a session without a room? */
  /*    why such a room should exists?  */
  /*  *\/ */
  /**
   * only exists to make operator[] possible for SessionUniverse
   *
   */
  np1secSession() 
  :myself("","")
    {
      assert(0); //not for calling
    };

  /**
   * Constructor, initiate by joining.
   */
  np1secSession(np1secUserState *us,
                std::string room_name,
                Cryptic* current_ephemeral_crypto,
                np1secMessage participants_info_message);

  /**
     Constructor being called by current participant receiving leave request
     
     - in new session constructor these will happen
     - drop leaver
     - computes session_id
     - compute z_sender (self)
     - set new session status to RE_SHARED
     
  */
  np1secSession(np1secUserState* us, std::string room_name, std::string leaver_id, ParticipantMap current_authed_participants);
    
  /**
     Constructor being called by operator+ and operator- to breed 
     new (unestablished) session
   
     - in new session constructor these will happen
       - computes session_id
       - compute z_sender (self)
       - set new session status to RE_SHARED

  */
  np1secSession(np1secUserState* us, std::string room_name, ParticipantMap current_authed_participants);
  /**
   * Almost copy constructor, we only alter the plist
   */
  /*np1secSession(np1secSession& breeding_session, 
    ParticipantMap participants_in_the_room);*/

  //TODO really one of these two are needed;
  np1secSession(np1secUserState *us, std::string room_name, np1secMessage join_message, ParticipantMap current_authed_participants);
  /**
   * access function for session_id;
   */
  SessionId my_session_id() { return session_id;}

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

  //friend all timer call backs
  friend /*static*/ void cb_send_heartbeat(evutil_socket_t fd, short what, void *arg);
  friend /*static*/ void cb_send_ack(evutil_socket_t fd, short what, void *arg);
  friend /*static*/ void cb_ack_not_received(evutil_socket_t fd, short what, void *arg);

};

#endif  // SRC_SESSION_H_
