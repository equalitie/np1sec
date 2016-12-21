# Writing an (n+1)sec client

The purpose of this document is to give a quick tutorial on how one can implement a secure E2E encrypted multi user chat using the (n+1)sec library. First, we'll describe a minimal abstract interface of an environment that the library will work in, following by the description on how the library interacts with such environment. For a dryer and denser explanation of the concepts explained here, please see the [(n+1)sec API documentation](np1sec_api.md).

# Communication with other clients

The library by itself is transport agnostic, that means that the responsibility of reliably transfering messages to other peers lays on the client implementor. For example, our example clients [jabberite] and [np1sec-test-client] both use libpurple/XMPP for this purpose, but it is important to note that there is nothing special about XMPP and that there is only a small set of properties that such transport must have to be able to work with (n+1)sec.

In fact, in this document we assume a centralized solution where each client has a working connection (e.g. TCP) to a server which simply echoes back every message it receives to all clients that are connected to it. Such centralized solution is used only for simplicity, removing the server in favor of a decentralized solution is also possible but the protocol used must ensure that *every node sees the messages arriving in the same order*.

With that said, we assume the following interface for the communication

```c++
    void server_on_connected();
    void server_on_disconnected();
    void server_on_message_received(const std::string& sender, const std::string& message);
    void server_send_message(const std::string& message);
```

# Interfaces

For the library to be able to interact with the rest of the world, the programmer needs to provide it with a set of functions by writing an implementation of pure virtual methods declared in the file [interface.h][interface-h-file].

In general, these methods are used by the library whenever one of these three events happen

- The library needs to send a message
- The library needs to set a timer
- An important state has changed that the programmer/user needs to know about.

We'll cover each case as we go in this document.

# Timers

Before going into details on how to bind the networking interface defined above with (n+1)sec, we need to take care of timers. The same way as the library is agnostig about the transport, it is also agnostic about the event loop it is used in. Such event loops usually provide a way to set up a non blocking timers which let us know when some given time duration has passed. As an example, the [gtk event loop][gtk_event_loop] provides the function [g_timeout_add][g_timeout_add], which we use in our test clients [jabberite][jabberite_timers] and [np1sec-test-client][plugin_timers].

To satisfy the library's requirement for timers, programmers need to implement these two virtual methods

```c++
virtual TimerToken* RoomInterface::set_timer(uint32_t duration_ms, TimerCallback* callback) = 0;
virtual void TimerToken::unset() = 0;
```

The first one does most of the work, it must tell the underlying event loop to start a timer (e.g. by using the `g_timeout_add` function) and invoke the `TimerCallback::execute()` method on the `callback` object once the timer fires. Additionaly the function must return an instance of the `TimerToken` class which is used when the library is no longer interested in the timer event being fired.

In our [_np1sec-test-client_ implementation][plugin_room-file], the `set_timer` function  simply returns an newly created instance of the [`np1sec_plugin::TimerToken` class][plugin_timers] (derives from `np1sec::TimerToken`) which  as well as taking care of canceling the timer, takes care of setting it up.

It is important to note that while the lifetime of the `callback` object is managed by the (n+1)sec library, the lifetime of an instance of `TimerToken` must be managed by the user of the library. That is, the `TimerToken` instance must be deleted once any one of these events happen

- After the timer fires and the `TimerCallback::execute()` method is invoked.
- After the instance of the `Room` class that created this `TimerCallback` is destroyed.
- Inside the `TimerToken::unset()` function upon invokation.

# Room and Conversations

The `Room` and `Conversation` classes are the most important interfaces a programmer needs to know about. The `Room` maintains a set of users that are able to send and receive encrypted messages with the twist that not every user can decrypt messages from every other user. Instead, any subset of users in the room who are able to decrypt each other's messages is maintained by the `Conversation` class. The set of existing conversations is as well maintained by the `Room` object.

There are two ways for an user to become part of a conversation, he or she can either create one, or accept an invitation from one or more users already in it. 

In our two (n+1)sec client implementations where we make use of the XMPP protocol, the `Room` correspods one-to-one with an [XMPP Multi User Chat (MUC)][xmpp-muc]. As there can be multiple XMPP MUC instances going on on one XMPP server, the server can handle multiple (n+1)sec rooms. In this document however, we're going to simplify things by removing this one level of indirection and assume only one `Room` per server. Thus everyone who is connected to the server will automatically (after authorization, see bellow) become part of that one room.

To use the `Room` and `RoomInterface` classes, we'll create a new class named `MyRoom` which owns an instance of `Room` and implements the `RoomInterface` interface
```c++
struct MyRoom : public RoomInterface {
    /* Constructor, destructor, etc. */
    ...
    
    /* Overwritten RoomInterface functions */
    ...

    /* Members */
    Room np1sec_room;
};
```
Similarly, we'll create a new class `MyConversation`
```c++
struct MyConversation : public ConversationInterface {
    /* Constructor, destructor, etc. */
    ...
    
    /* Overwritten ConversationInterface functions */
    ...

    /* Members */
    MyRoom* my_room;
    // The lifetime of np1sec_conversation is managed by the (n+1)sec library.
    Conversation* np1sec_conversation;
};
```

# Bind network events
Next we need to bind the networking interface defined in above with (n+1)sec. There are really only three network related events that the library needs to know: When the connection is established, when we receive a message and how to send a message.

```c++
std::unique_ptr<MyRoom> g_room;

void server_on_connected()
{
    g_room = new MyRoom(this, my_username, my_public_private_key_pair);
    // This tells the library that we're connected and it can start sending messages to the server.
    g_room->connect();
}

void server_on_disconnected()
{
    g_room.reset()
}

// We have received an encrypted message from the server, lets tell it to the library.
void server_on_message_received(const std::string& sender, const std::string& message)
{
    if (!g_room) return;
    g_room->np1sec_room.message_received(sender, message);
}
```
When the library wants to send a message it will invoke the virtual `RoomInterface::send_message` function, let's implement it
```c++
struct MyRoom : public RoomInterface {
    ...
    void send_message(const std::string& message) override {
        serer_send_message(message);
    }
    ...
};
```
# Creating channels
Now that we have timers and basic network IO in place, we can start manipulating the (n+1)sec's internal state. The first thing we'll want to do is to create a new Conversation by invoking the `Room::create_conversation()` function. Once the conversation has been created, the library will invoke `RoomInterface::created_conversation` which we need to implement

```c++
struct MyRoom : public RoomInterface {
    ...
    ConversationInterface* created_conversation(Conversation* conversation) override {
        return new MyConversation{this, conversation};
    }
    ...
};
```
A conversation created this way initially contains only one user in it, the caller of the `Room::create_conversation()` function. We can start sending encrypted messages into this conversation by calling the `Conversation::send_chat(const std::string& message)` function, but since we're the only ones in there, no one else would be able to decrypt those messages. Thus we need to _invite_ other users into the conversation.

# Inviting others into Conversation
When a user invokes `Room::connect`, a handshake with the other nodes connected to the server starts. Among other things, this handshake verifies that the connecting user possess a valid private and public cryptographic key pair. Once this is done, the library notifies us through the `user_joined` callback.
```c++
virtual void RoomInterface::user_joined(const std::string& username, const PublicKey& public_key) = 0;
```
We'll talk about the `public_key` parameter in more detail in the [Authentication](#Authentication) section. For now it suffices to say that when we want to invite this user into a Conversation, these are the `username` and `public_key` parameters we need to use when invoking the function
```c++
void Conversation::invite(const std::string& username, const PublicKey& public_key);
```
Once the invited user receives this invitation, the library shall notify her by executing the callback
```c++
virtual void RoomInterface::invited_to_conversation(Conversation* conversation, std::string& username) = 0;
```
From that point on, the user may decide to accept the invitation by invoking `Conversation::join` or reject it by invoking `Conversation::leave`. When that user decides to _join_, he transitions from the state _Invited_ into state _Joining_. This is indicated to that user through the `ConversationInterface::joining()` callback and to the rest of the users in that conversation through the `ConversationInterface::user_joining(const std::string& username)` callback.

While the user is in this state, it is possible that she may be able to decrypt _some_ of the messages circulating in that conversation and also that _some_ of the other already joined or joining users may decrypt her messages. To make sure _everyone_ who is in state _Joined_ in that conversation is able to read her messages, she needs to wait for the `ConversationInterface::joined()` callback (equivalently, others need to wait for the `ConversationInterface::user_joined(username)` callback).

This is the crux of the invitation process. For more details about how to transition between the different states in the Conversation, please consult the [Conversation and Users section of the (n+1)sec API document](np1sec_api.md#conversations-and-users).

# Authentication
To avoid the man in the middle attack, (n+1)sec exposes (through its API) each user's public key. It does so in two occasions. The first time is when a user joins the Room through the `RoomInterface::user_joined(username, public_key)` callback. This public key should be consulted and verified by the user of the client before that new user is to be invited into a conversation.

Another occasion when the library us with a _(username, public_key)_ pair is when a user with this _username_ joins a conversation through the `ConversationInterface::user_authenticated(username, public_key)` callback. This is because someone else may have carelessly invited this user without actually taking care with checking that the public key really belongs to this `username`. As such, it is up to us to verify that user's identity once he enters the conversation.

It is expected that clients shall maintain a database of _(username, public_key)_ pairs to automatically verify that a particular user really is who he claims to be. Also, whenever a new user shows up in the room who is not yet in the database, the client should show a dialog asking to confirm that the _public_key_ belongs to that user. If the _username <-> public_key_ binding is confirmed, the client should add the new pair to the database and allow sending invitation to that user.

Note that at the time of writing this document, neither [jabberite][jabberite] nor [np1sec-test-client][np1sec-test-client] clients ask the user for this confirmation. Which is one of the biggests reasons we're not recommending to rely on them being secure.

[xmpp-muc]: http://xmpp.org/extensions/xep-0045.html
[interface-h-file]: https://github.com/equalitie/np1sec/blob/master/src/interface.h
[room-class]: https://github.com/equalitie/np1sec/blob/master/src/room.h
[conversation-class]: https://github.com/equalitie/np1sec/blob/master/src/conversation.h
[jabberite]: https://github.com/equalitie/np1sec/tree/master/test/jabberite
[np1sec-test-client]: https://github.com/equalitie/np1sec-test-client
[gtk_event_loop]: https://developer.gnome.org/gtk3/stable/gtk3-General.html
[g_timeout_add]: https://developer.gnome.org/glib/stable/glib-The-Main-Event-Loop.html#g-timeout-add
[jabberite_timers]: https://github.com/equalitie/np1sec/blob/master/test/jabberite/jabberite.cc
[plugin_timers]: https://github.com/equalitie/np1sec-test-client/blob/master/src/timer.h
[plugin_room-file]: https://github.com/equalitie/np1sec-test-client/blob/master/src/room.h
