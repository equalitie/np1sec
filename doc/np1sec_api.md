(n+1)sec API Spec
=================
        (n+1)sec multiparty secure messaging Library
			  v1.0.1, May 2015

libnp1sec is a library which implement (n+1)sec protocol in c++ and
offers a c++ for the chat clients. (n+1)sec bring end-to-end
security for multi(2+)party chat. This means that by no means you need
to rely on the chat server to keep you conversation secure.

For more information on (n+1)sec protocol, see
https://learn.equalit.ie/wiki/Np1sec

How to use np1sec library
=========================
1. Initialization

1.1. Setup the ApsOps

(n+1)sec needs a set of callback function to communicate with the chat client (for sending messages, for announcing secure join and leave, for setting up timers,...). It also needs to know the latency of the chat protocol to judge about the unresponsiveness of other participant. The client need to store these information in an np1sec::AppOps object:

    AppOps ops = new AppOps(hundred_mili_sec, one_sec, hundred_mili_sec, hundred_mili_sec);

where

    AppOps(uint32_t ACK_GRACE_INTERVAL,
           uint32_t REKEY_GRACE_INTERVAL,
           uint32_t INTERACTION_GRACE_INTERVAL,
           uint32_t BROADCAST_LATENCY);

And then assign the pointer to different functions:

        ops->send_bare = send_bare;
        ops->join = new_session_announce;
        ops->leave = new_session_announce;
        ops->display_message = display_message;
        ops->set_timer = set_timer;
        ops->axe_timer = axe_timer;

* send_bare is called by (n+1)sec to send message on chat channel (after encryption).
* join is called when someone successfully negotiate a group key and joined a secure session.
* leave is called when someone leaves and a new key is negotiated after they left.
* display_message is called when a session message has been decrypted and is ready to be displayed.
* set_timer is called whenever (n+1)sec needs to start a timer with time out call back
* axe_timer is called whenever a timer is no longer needed.

All the information concerning each user is stored in a UserState object. It includes long term public key, the list of room, the user has joined, the ephemeral keys to each room and the state of the participant in each room (joined, in-session, etc). UserState object needs to be created before any request np1sec library can be handled:

    np1sec::UserState user_state(username, ops);

Client can optionally send a pointer to the ed25519 long term key pair as
the third parameters.

You will also need an OtrlUserState.  An OtrlUserState encapsulates the
list of known fingerprints and the list of private keys, so it should be
"one per user".  Many OTR-enabled programs (such as IM clients) only have a 
single user, so for them, you can just create a single one, and use it
thoughout.  Create an OtrlUserState as follows:

    userstate = otrl_userstate_create();

If you need to free an OtrlUserState:

    otrl_userstate_free(userstate);

To read stored private keys:

    otrl_privkey_read(userstate, privkeyfilename);

To read stored instance tags:

    otrl_instag_read(userstate, instagfilename);

To read stored fingerprints:

    otrl_privkey_read_fingerprints(userstate, fingerprintfilename,
	    add_app_info, add_app_info_data);

add_app_info is a function that will be called in the event that a new
ConnContext is created.  It will be passed the add_app_info_data that
you supplied, as well as a pointer to the new ConnContext.  You can use
this to add application-specific information to the ConnContext using
the "context->app" field, for example.  If you don't need to do this,
you can pass NULL for the last two arguments of
otrl_privkey_read_fingerprints.

2. Setting up the UI functions

You need to let the library know how to do any UI it might require
(error messages, confirming new fingerprints, etc.).  To this end, you
need to define a number of UI functions, and collect them in a
OtrlMessageAppOps struct.

The first parameter of every UI function is "void *opdata".  This is a
pointer you pass to the library, and it will pass back (opaquely) to the
UI functions when it calls them.  You can use this to keep track of
state or any other information.

You will need to include proto.h and message.h, and you can find a list
of the UI functions in message.h.

3. Sending messages

When you have a message you're about to send, you'll need to know four
things: you account name, the protocol id, the name of the recipient, 
their instance tag, and the message.

OTR protocol version 3 introduces the notion of "instance tags." A
client may be logged into the same account multiple times from different
locations. An instance tag is intended to differentiate these clients. 
When sending a message, you may also specify a particular instance tag, 
or use meta instance tags like OTRL_INSTAG_MOST_SECURE.

The protocol id is just a unique string that is used to distinguish
the user foo on AIM from the user foo on MSN, etc.  It can be anything
you like, so long as you're consistent, but if you've got nothing better
to use, you may as well use the ids from gaim.  (Programs that use the
same protocol ids can share fingerprint and private key files.)  The
gaim protocol id for AIM/ICQ is "prpl-oscar".

Note that a name does not uniquely identify a user (as shown by the
"foo" example above).  Even if you know both the name and the protocol,
it may not identify the user, since there may be multiple "foo" users on
IRC, on different servers.  But the *three* items (your account name,
protocol id, their name) _must_ uniquely identify a user, so your
account name needs to include any network identifier, such as a server
name.  Examples would be "foo@irc.freenode.net" or "foo@jabber.org".
Protocols such as AIM that do not have separate networks can just use
"foo", of course.

To encrypt the message (if necessary; the library keeps track of which
users you have secure connections to, so you should *always* call this
next function), simply do this:

    gcry_error_t err;
    char *newmessage = NULL;

    err = otrl_message_sending(userstate, &ui_ops, opdata, accountname,
	    protocolid, recipient_name, instag, message, tlvs, 
	    &newmessage, fragPolicy, contextp, add_app_info, 
	    add_app_info_data);

add_app_info and add_app_info_data are as above, and may be NULL.

tlvs should usually be NULL.  If it's not, then it points to a chain of
OtrlTLVs which represent machine-readable data to send along with this
message.

If contextp is not NULL, it will be set to the context that was used
for sending the message.

If err is non-zero, then the library tried to encrypt the message,
but for some reason failed.  DO NOT send the message in the clear in
that case.

If newmessage gets set by the call to something non-NULL, then you
should replace your message with the contents of newmessage, and
send that instead.

Once the message is encrypted, it may still be too large to send over
the network in a single piece.  To check the maximum message size and
break your message into fragments if necessary, do this:

    gcry_error_t err;
    char *extrafragment = NULL;

    err = otrl_message_fragment_and_send(&ui_ops, opdata, context,
	    message, fragmentPolicy, extrafragment);

fragmentPolicy determines which, if any, fragments to return instead
of sending them immediately.  For example, you may wish to send all 
fragments except the last one, which is handled differently.  Valid
policies may be found in proto.h.

If err returns a nonzero value from fragment_and_send, the application
tried to break your message into fragments but failed for some reason.
You may still attempt to send the original message, but it might be
rejected if it too large.

When you're done with newmessage, you must call

    otrl_message_free(newmessage)

4. Receiving messages

Receiving messages is similarly straightforward.  Again, you need to
know four things: your account name, the protocol id, the sender's name,
and the message.

    int ignore_message;
    char *newmessage = NULL;

    ignore_message = otrl_message_receiving(userstate, &ui_ops, opdata,
	    accountname, protocolid, sender_name, message, &newmessage,
	    &tlvs, contextp, add_app_info, add_app_info_data);

add_app_info and add_app_info_data are as above, and may be NULL.

If contextp is not NULL, it will be set to the context that was used
for receiving the message.

If otrl_message_receiving returns 1, then the message you received was
an internal protocol message, and no message should be delivered to the
user.

If it returns 0, then check if newmessage was set to non-NULL.  If so,
replace the received message with the contents of newmessage, and
deliver that to the user instead.  You must call
otrl_message_free(newmessage) when you're done with it.

If otrl_message_receiving returns 0 and newmessage is NULL, then this
was an ordinary, non-OTR message, which should just be delivered to the
user without modification.

If tlvs is set to non-NULL, then there is machine-readable data that was
sent along with this message.  Call otrl_tlv_free(tlvs) when you're done
dealing with it (or ignoring it).

5. Socialist Millionaires' Protocol

The Socialist Millionaires' Protocol (SMP) is a way to detect
eavesdropping and man-in-the-middle attacks without requiring users to
work with fingerprints.  This feature was added to OTR starting in
version 3.1.0.  To learn how to modify your application to use SMP, read
the UPGRADING file.

TOOLKIT

Along with the library, this package comes with the OTR Messaging
Toolkit.  This toolkit is useful for analyzing and/or forging OTR
messages.  Why do we offer this?  Primarily, to make absolutely sure
that transcripts of OTR conversations are really easy to forge after the
fact.  [Note that *during* an OTR conversation, messages can't be forged
without real-time access to the secret keys on the participants'
computers, and in that case, all security has already been lost.]
Easily forgeable transcripts help us provide the "Deniability" property:
if someone claims you said something over OTR, they'll have no proof, as
anyone at all can modify a transcript to make it say whatever they like,
and still have all the verification come out correctly.

Here are the six programs in the toolkit:

 - otr_parse
   - Parse OTR messages given on stdin, showing the values of all the
     fields in OTR protocol messages.

 - otr_sesskeys our_privkey their_pubkey
   - Shows our public key, the session id, two AES and two MAC keys
     derived from the given Diffie-Hellman keys (one private, one public).

 - otr_mackey aes_enc_key
   - Shows the MAC key derived from the given AES key.

 - otr_readforge aes_enc_key [newmsg]
   - Decrypts an OTR Data message using the given AES key, and displays
     the message, if the key was correct.
   - If newmsg is given, replace the message with that one, encrypt
     and MAC it properly, and output the resulting OTR Data Message.
     This works even if the given key was not correct for the original
     message, so as to enable complete forgeries.

 - otr_modify mackey old_text new_text offset
   - Even if you can't read the data because you don't know either
     the AES key or the Diffie-Hellman private key, but you can make a
     good guess that the substring "old_text" appears at the given
     offset in the message, replace the old_text with the new_text
     (which must be of the same length), recalculate the MAC with the
     given mackey, and output the resulting Data message.
   - Note that, even if you don't know any text in an existing message,
     you can still forge messages of your choice using the otr_readforge
     command, above.

 - otr_remac mackey sender_instance receiver_instance flags keyid keyid
   pubkey counter encdata revealed_mackeys
   - Make a new OTR Data Message, with the given pieces (note that the
     data part is already encrypted).  MAC it with the given mackey.

NOTES

Please send your bug reports, comments, suggestions, patches, etc. to us
at the contact address below.
