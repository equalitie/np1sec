(n+1)sec API Documentation
=================
This document describes only the public API, the definition of the protocol is
elsewhere.

## Public API

There are five different classes that a user of this library must utilize to
properly use it. These are:

* `Room` and `RoomInterface`
* `Conversation` and `ConversationInterface`
* `TimerToken`

The `Room` and `Conversation` classes are used to manipulate the library's
internal state and their `Interface` counterparts are used by the library to
provide the user with a feedback whenever an important state change happens due
to network or timing events.

## Room
**Main class:** src/room.h<br/>
**Interface:** src/interfaces.h/RoomInterface

Room is a central concept in this library. It contains a collection of
conversations, and provides a communication link to all of them. It also
contains a list of authenticated users that we can invite, updated via callbacks
present in the `RoomInterface`. This list is not strongly related to the list of
people in particular conversations -- a user can be in a conversation without
being in the room list.

A room can create a conversation by calling the asynchronous
`Room::create_conversation()` function. Once the process of creating a
conversation is finished, the user is announced through the
`RoomInterface::conversation_created` callback. A conversation created in this
way has only the creator in it. Another way a conversation may be created is
through invitation by some other (n+1)sec user into her channel. In such case,
the `Room::invited_to_conversation` callback is invoked with users already
present in the conversation and us.

Before the `Room` object can be used, we have to call `Room::connect()`. This
tells the library that the communication link is ready to be used. On breakage,
the library calls the `RoomInterface::disconnected()` function and destroys all
existing conversations afterwards.

**Caveat:** One cannot call any `Room` non-const functions from `RoomInterface`
callbacks. This avoids reentrancy. However, conversation functions and Room
accessors are OK to be used.

## Conversations and Users
**Main class:** src/conversation.h<br/>
**Interface:** src/interfaces.h/ConversationInterface

A Conversation represents an encrypted chat session. It maintains a set of users
and their conversation state.

Users are not represented by a dedicated C++ class. Instead they are uniquely
represented by their name (a std::string). They have three different states
associated with them. One of them is accessed through the `Room` class and
indicates whether the user is (n+1)sec enabled. The other two states are
accessed through the `Conversation` class and represent users' authentication
status and the ability to participate in the conversation. 


```
                   +---------------------------+
                   | User's conversation state |                
                   +---------------------------+

        +----------------------------------------------------+
        |                                                    |
        |     R::create_conversation                         |
        |       RI::created_conversation                     |
        |           |                                        |
        |  +-----------------------------------+             |
        |  |                                   |             |
        |  |   C::cancel_invite                |             |
        |  |   C::vote_kick                    |             |
        |  |   C::leave                        |             |
        |  |     CI::invitation_canceled       |             |
        |  |     CI::left                      |             |
        |  |       |                           |             |
        |  |  +---------+           +----------|-------+     |
        |  |  |         |           |          |       |     |
        V  |  V         |           |          V       |     |
      Not invited --> Invited --> Joining --> Joined --+---->+
                   |           |           |              |
                   |           |           |           C::leave
                   |           |           |           C::vote_kick    
                   |           |           |             CI::user_left
                   |           |           |             CI::left     
                   |           |           |
                   |           |        CI::user_joined
                   |           |        CI::joined
                   |           |
                   |        C::join
                   |          CI::user_joining
                   |          CI::joining
                   |                             
                C::invite                         +-------------------------------------+
                  CI::user_invited                | Legend: C  := Conversation          |
                  RI::invited_to_conversation     |         CI := ConversationInterface |
                                                  |         R  := Room                  |
                                                  |         RI := RoomInterface         |
                                                  +-------------------------------------+

```
We say that a user is a `Participant` if she is either in the `Joining` or
`Joined` state.  The `Joining` state is only temporary and indicates that _some_
of the messages sent may be decoded by _some_ of the participants and also that
the user may be able to decode _some_ of the messages other participants sent. A
user cannot tell whether someone is in the `Joined` state until that user has
joined as well.

Participants who are in the `Joined` state may call `Conversation::send_chat()`
and receive `ConversationInterface::message_received()` events to participate in
the secure conversation.

Each participant and each user may or may not be authenticated.

Participants may invite other users into the conversation. If these users were
previously in the `Not invited` state, they'll then switch to the `Invited`
state, from where they can "join" the conversation to become participants. While
in the `Invited` state, the inviters may cancel the invitation by using the
`Conversation::cancel_invite` function, in which case the user becomes `Not
invited` again. The same implicitly happens if the inviters leave the
conversation or other participants call `Conversation::vote_kick` against the
invited users.

Participants can vote to kick not only invitees but also other participants. In
such case the conversation is split into two descendants when a consensus is
reached.

To leave a conversation voluntarily, user calls `Conversation::leave`. Whenever
(with exceptions described below) the user transitions to the `Not invited`
state, callback `ConversationInterface::left` is executed and the conversation
is deleted afterwards.

There are two cases when the `ConversationInterface::left` callback (or any
other conversation callback) will not be executed:

* When user calls `Conversation::leave(bool detach)` with the `detach` argument
  set to `true`.
* Or after `RoomInterface::disconnected` callback is called.

## Timers
**Interface:** src/interfaces.h/TimerToken

The (n+1)sec library makes use of timers to detect disconnection (among others).
To stay independent from the event loop it is used in as much as possible, users
of the library are required to implement few timer related function.

When the (n+1)sec library needs to start a timer, it calls the
`RoomInterface::set_timer` function

```
	virtual TimerToken* RoomInterface::set_timer(uint32_t interval, TimerCallback* callback) = 0;
```

Inside it, the user has to set up a timer of her choice which - once the timer
starts - eventually executes the `TimerCallback::execute` method. The return
value of the `set_timer` function needs to be an instance of an object that
implements the `TimerToken` interface.

The purpose of the `TimerToken` object is to allow the library to cancel the
timer at any time by calling the `TimerToken::unset` method after which the
`TimerToken::execute` method must not be called on that particular `callback`
object.

Note that the library doesn't make use of virtual destructors. This means that
the responsibility to destruct an object lays in the library/executable that
created it.  That is, users of the library must not explicitly destroy the
instance of the `TimerCallback` class, but must destruct the instance of
`TimerToken` when one of these happens:

* Right after the `TimerCallback::execute` function is called
* Inside the `TimerToken::unset` function
* Right after the `Room` that created this `TimerToken` is destroyed

## Example code

There are currently two test clients that use this library. The first one is
called `jabberite`, is text-based and is [part of this
repository](https://github.com/equalitie/np1sec/tree/master/test/jabberite).
The other one is called
[np1sec-test-client](https://github.com/equalitie/np1sec-test-client) and is
meant to be used as a plugin for the [Pidgin messenger](https://pidgin.im/).
Both use the libpurple messaging library under the hood.
