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

#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>

#include "common.h"
#include "interface.h"
#include "participant.h"
#include "message.h"
#include "crypt.h"
#include "session_id.h"

#include "transcript_consistency.h"

namespace np1sec
{

class UserState;
class Session;
class Room;


class RoomAction
{
    // historically RoomAction was the way to inform chat client about */
    // actions, however we decided the main tool for action transmission */
    // to chat client are callback function */

    // the only real action type is only */
    // activate which signal changing active session and hence */
    // cryptographically verifiable join and leave. */
  public:
    enum ActionType {
        NO_ACTION,
        BAD_ACTION,
        NEW_SESSION, // JOIN
        NEW_PRIORITY_SESSION, // LEAVE
        PRESUME_HEIR // GROUP_KEY_GENERATED
        /*     JOIN, */
        /*     LEAVE, */
        /*     REKEY, */
        /*     NEW_MESSAGE */
    };

    ActionType action_type;
    // The user which joined, left or sent a message.
    // UnauthenticatedParticipant acting_user; //it is enough to be just a nick
    std::string acting_user_nick;
    Session* bred_session = nullptr;
    /**
     * construtor. given no arugement it results in NO_ACTION
     */
    RoomAction(ActionType action = NO_ACTION, std::string acting_user_nick = "")
        : action_type(action), acting_user_nick(acting_user_nick)
    {
    }
};

const RoomAction c_no_room_action;

/**
 * This class is encapsulating all information and action, a user needs and
 * performs in a session.
 */
class Session
{
  protected:
    UserState* us;
    std::string room_name;

    // TODO:: we should probably delete this and just directly use UserState->myself
    // no reason to copy the same thing for every session.
    ParticipantId myself; // to keep the nickname and the long term id key
    // these are necessary to send join request

    Cryptic cryptic;
    Cryptic future_cryptic;

    size_t my_index;

    /**
     * Stores Transcritp chain hashes indexed by received message id
     */
    std::map<MessageId, ConsistencyBlockVector> received_transcript_chain;

    /**
     * Stores the Transcript chain of hashes of all sent messages by the
     * thread user index by own_message_id
     *
     * When a message of our is received we extract the sender_message_id
     * to index it here and kill the timer and check the consistency.
     *
     * We also update message id, and we check for the consistency for
     * the orders of own_message_id and the message_id
     */
    std::map<MessageId, ParticipantConsistencyBlock> sent_transcript_chain;

    /**
     * Inserts a block in the send transcript chain and start a
     * timer to receive the ack for it
     */
    void update_send_transcript_chain(MessageId own_message_id, HashStdBlock message_hash);

    /**
     * - kills the send ack timer for the message
     * - Fill our own transcript chain for the message
     * - Perform parent consistency check
     */
    void perform_received_consisteny_tasks(Message received_message);

    // participants data:
    /**
     * Keeps the list of the updated participants in the room once the
     * join/accept or farewell finishes.
     */
    ParticipantMap participants;

    /**
     * Keep lists of those who left. This is necessary otherwise
     * two people leave from the same session, create a deadlock
     * as none of them are there to confirm the new session, there
     * fore many can leave one session but only one can join.
     */
    ParticipantMap zombies;

    /**
     * Keep lists of the list of participants of the session
     * being confirmed before us.
     */
    ParticipantMap parental_participants;

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
     *  2. Is no longer valid for subsequent sessions. (new session need new confirmation). (In contrast to
     * authenticated for e.g.)
     *
     */
    std::vector<bool> confirmed_peers;

    /**
      * Insert new message hash into transcript chain
      *
      */
    void add_message_to_transcript(std::string message, uint32_t message_id);

    /**
      * Generate acknowledgement timers for all other participants
      *
      */
    void start_ack_timers(const Message& received_message);

    /**
      * Construct and start timers for acking received messages
      */
    void start_acking_timer();

    /**
     * disarm acking timer because we sent a message
     */
    void stop_acking_timer();

    SessionId session_id;
    // TODO - Move these into the Cryptic class where appropriate
    HashBlock session_key;
    HashBlock session_confirmation;

    void* send_ack_timer = nullptr; // to send an ack to acknowledge all messages up to now
    void* farewell_deadline_timer = nullptr; // wait till you get everybody's hash to check before leave actually
    void* rejoin_timer = nullptr; // try to rejoin
    void* session_life_timer = nullptr; // start new session with the same participant but different keys

    MessageId last_received_message_id = 0;
    MessageId own_message_counter = 0; // sent message counter
    MessageId leave_parent = 0;
    // Depricated in favor of raison detr.
    // tree structure seems to be insufficient. because
    // sid only encode the session structure but not
    // why sid is generated it could be generated for
    // two different reasons, though I can't come
    // up with an example.

    static const int32_t c_my_right = 1;
    static const int32_t c_my_left = -1;

    /**
     * it is invoked only once to compute the session id
     * if one need session id then they need a new session
     * as such it dies on re-computation.
     */
    void compute_session_id();

    /**
     * compute the right secret share
     * @param side  either c_my_right = 1 or c_my_left = 1
     */
    void secret_share_on(int32_t side, HashBlock hb);

    static ParticipantMap participants_list_to_map(const UnauthenticatedParticipantList& session_view)
    {
        ParticipantMap converted_map;

        for (UnauthenticatedParticipantList::const_iterator view_it = session_view.begin();
             view_it != session_view.end(); view_it++) {
            converted_map.insert(
                std::pair<std::string, Participant>(view_it->participant_id.nickname, Participant(*view_it)));
            converted_map[view_it->participant_id.nickname].authenticated = view_it->authenticated;
        }

        return converted_map;
    }

    void populate_peers_from_participants()
    {
        peers.clear();
        for (ParticipantMap::iterator it = participants.begin(); it != participants.end(); it++) {
            peers.push_back(it->first);
        }

        keep_peers_in_order_spot_myself();
        // session id doesn't need peers vector to be computed
        // so we just check if it is not set, it is the time to be computed
        if (!session_id.get())
            compute_session_id();
    }

    /**
     * generate a session view by iterating over session_view
     */
    UnauthenticatedParticipantList session_view()
    {
        UnauthenticatedParticipantList session_view;
        for (size_t i = 0; i < peers.size(); i++) {
            session_view.push_back(UnauthenticatedParticipant(
                participants[peers[i]].id, hash_to_string_buff(participants[peers[i]].raw_ephemeral_key),
                participants[peers[i]].authenticated));
        }

        return session_view;
    }

    /**
     * everytime that peers are modified we need to call this function to
     * to keep it in order
     *
     * @return if we can't spot ourselves the session isn't meant for us
     *
     */
    void keep_peers_in_order_spot_myself()
    {

        std::sort(peers.begin(), peers.end());

        std::vector<std::string>::iterator my_entry = std::find(peers.begin(), peers.end(), myself.nickname);
        if (my_entry == peers.end()) {
            logger.debug("the message wasn't meant to us", __FUNCTION__, myself.nickname);
            throw InvalidRoomException(); // The idea is that if we got an invalid room
            // then we don't go for creating session;
        }

        my_index = std::distance(peers.begin(), my_entry);

        // we trust ourselves so no need to auth ourselves neither be_authed_to
        participants[peers[my_index]].authenticated = true;
        participants[peers[my_index]].authed_to = true;

        for (size_t i = 0; i < peers.size(); i++) {
            // participants[peers[i]].thread_user_as_participant = &participants[peers[my_index]];
            // if we copy the session the pointer
            // //to thread user as participant is not valid anymore. This is obviously digusting
            // //we need a respectable copy constructor for Session
            participants[peers[i]].index = i;
        }

        // flush the confirmation
        confirmed_peers.clear();
        confirmed_peers.resize(peers.size());
    }

    /**
     * prepare a new list of participant for a new session
     * replacing future key to current key and drop zombies
     */
    ParticipantMap future_participants();

    /**
     * returns participants - parental_participants
     * it shows what is the session suppose to add or
     * drop it is a replacement for raison_detre
     *
     */
    ParticipantMap delta_plist();

    /**
     * compute the session confirmation of the based on the value of
     * the shared key
     */
    void compute_session_confirmation();

    /**
     * add the hash of( the session key | session id) as the first element
     * of transcript chain.
     */
    void account_for_session_and_key_consistency();

    /**
     * check if session confirmation has been computed correctly
     */
    bool validate_session_confirmation(Message confirmation_message);

    /**
     * if the message is signed (that's anything but join request)
     * this function verify it
     *
     * throw authentication exception in case it fails
     */
    void verify_peers_signature(Message& received_message)
    {
        // If the participant isn't in the list then don't bother
        if (participants.find(received_message.sender_nick) == participants.end()) {
            logger.error("authing participant " + received_message.sender_nick + " is not in the session ");
            throw InvalidParticipantException(); // or show we throw invalid participants?
        }

        // we need to check the signature of the message here
        if (!received_message.verify_message(participants[received_message.sender_nick].ephemeral_key))
            throw AuthenticationException();
    }

    void group_enc();
    void group_dec();

    /**
     * Simply checks the confirmed array for every element be true
     */
    bool everybody_confirmed();

    /**
     * Simply checks the confirmed array for every element be false
     */
    bool nobody_confirmed();

    /**
     * Simply checks the participant map  for every element be authed.
     */
    bool everybody_authenticated_and_contributed();

    // Messaging functions
    /**
    * When session changes with no need to inform
    * new people about it (leave) then this function is
    * is used (no participant_info)
    */
    void send_new_share_message();

    /**
     *   Joiner call this after receiving the participant info to
     *    authenticate to everybody in the room
     */
    void joiner_send_auth_and_share();

    /**
       Preparinig PARTICIPANT_INFO Message

       current user calls this to send participant info to joiner
       and others
       sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
    */
    void send_view_auth_and_share(std::string joiner_id = std::string(""));

  public:
    /**
     * (n+1)sec sessions are implemented as finite state machines.
     * Each message transaction might ends up in state change.
     * this is a generic class to store every state and manage its
     * transition, illigiblity etc
     *
     */
    enum SessionState {
        NONE,
        JOIN_REQUESTED, // The thread has requested to join
                        // by sending ephemeral key
        RE_SHARED,      // key is being made, thread has been sent its share,
                        // waiting for more shares. This is the same as
                        // AUTHED_JOINER but for leave procedure where there
                        // is no need to auth

        GROUP_KEY_GENERATED, // The thread has computed the session
                             // key and has sent the conformation
        IN_SESSION,          // Key has been confirmed
        LEAVE_REQUESTED,     // Leave requested by the thread, waiting
                             // for final transcirpt consitancy check
        STALE, // A Mark that a new session with the same goal need to be created
        DEAD, // Won't accept receive or sent messages, possibly throw up
        TOTAL_NO_OF_STATES // This should be always the last state
    };

    /**
     * When a session request the creation of a session it inform
     * the sessoin of the condition it has been created
     */
    enum SessionConceiverCondition { CREATOR, JOINER, ACCEPTOR, PEER };

  protected:
    // should only be changed in constructor or state transitor
    SessionState my_state = DEAD;
    typedef std::pair<SessionState, RoomAction> StateAndAction;

    /**
     * sends session confirmation if everybody is contributed and authenticated
     * returns DEAD state if fails to decrypt the group key.
     *         GROUP_KEY_GENERATED otherwise
     *          the current state if not everybody authenticated
     */
    Session::StateAndAction send_session_confirmation_if_everybody_is_contributed();

    /**
     list of state transitors:
     J: joining C: current

     J:
     in join

     receive accept (matching/nonmatching sid): -> Reply with auth to everybody on the list + (new) shares. set sid.
     add/replace/invalidate shares.

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
     *  For join user calls this when receivemessage has type of PARTICIPANTS_INFO
     *
     *  sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender
     *
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
    StateAndAction auth_and_reshare(Message received_message);

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
    StateAndAction confirm_auth_add_update_share_repo(Message received_message);

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
    StateAndAction mark_confirmed_and_may_move_session(Message received_message);

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
    StateAndAction send_farewell_and_reshare(Message received_message);

    /**
     * for immature leave when we don't have leave intention
     */
    RoomAction shrink(std::string leaving_nick);

    /**
     * - check the consistency of all participants for the parent leave message
     *
     *  @return true if everybody has farewelled (consistent or not)
     */
    bool check_leave_transcript_consistency();

  public:
    /**
     * access function for state
     */
    SessionState get_state() { return my_state; }

    /**
     * tells if rejoin is active
     */
    bool is_rejoin_timer_active() { return (rejoin_timer != nullptr); };

    /**
     * tells if rejoin is active
     */
    void arm_rejoin_timer();

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
    RoomAction state_handler(Message receivd_message);

    /**
     * change the state to DEAD. it is needed when we bread a new
     * session out of this session.
     * it also axes all of the timers
     */
    void commit_suicide();

    /**
     * stops all timers
     */
    void disarm_all_timers();

    /**
     * same as suicide but it is marked so its list be used later
     */
    void stale_me()
    {
        disarm_all_timers();
        my_state = STALE;
    }

   /**
     * When a user wants to send a message to a session it needs to call its send
     * function.
     */
    void send(std::string message, Message::MessageSubType message_type);

    /**
     *  Constructor
     *
     *  @param conceiver: the role of thread user in the session being constructed
     */
    Session(SessionConceiverCondition conceiver, UserState* us, std::string room_name,
                  Cryptic* current_ephemeral_crypto, const ParticipantMap& current_participants = ParticipantMap(),
                  const ParticipantMap& parent_plist = ParticipantMap());

    // Session(UserState *us, std::string room_name,  Cryptic* current_ephemeral_crypto, Message
    // join_message, ParticipantMap current_authed_participants);

    /**
     * access function for session_id;
     */
    SessionId my_session_id() { return session_id; }

    /**
     * When a message is received from a session the receive function needs to be
     * called to decrypt. It updates the session status and returns the decrypted
     * message to be shown, it might be null if the message was a meta message.
     */
    StateAndAction receive(Message encrypted_message);

    /**
     * is called by the room to send "I'm leaving" message
     * it changs session state to LEAVE_REQUESTED
     */
    void leave();

    /**
     * Destructor, session should be destroyed at leave.
     */
    ~Session();

    // friend all timer call backs
    friend void cb_send_heartbeat(void* arg);
    friend void cb_send_ack(void* arg);
    friend void cb_ack_not_received(void* arg);
    friend void cb_ack_not_sent(void* arg);
    friend void cb_leave(void* arg);

    friend void cb_rejoin(void* arg);
    friend void cb_re_session(void* arg);

    friend Room;
};

} // namespace np1sec

#endif // SRC_SESSION_H_
