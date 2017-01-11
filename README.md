(n+1)sec
======

(n+1)sec is a Free (libre), end-to-end secure, synchronous, multi-party messaging protocol, authored by eQualit.ie with support from the Open Technology Fund. The (n+1)sec project, similar to the OTR (off-the-record) project, makes it possible to have secure instantaneous communications between people. (n+1)sec extends upon OTR in supporting not just one-to-one chats, but also chats between arbitrary groups of people. Like OTR, (n+1)sec is built on top of arbitrary chat infrastructure systems, such as XMPP, and can be implemented in any client for these systems.

![(n+1)sec](https://learn.equalit.ie/mw/images/7/7f/Np1sec-web.jpg)

The protocol underlying this multiparty communication security is described in this [paper](https://learn.equalit.ie/wiki/Np1sec). An experimental GUI client, in the form of a Pidgin plugin is [here](https://github.com/equalitie/np1sec-test-client). A command line client, called Jabberite, is included in this repository and described [below](https://github.com/equalitie/np1sec/blob/master/README.md#testing-np1sec). This client is used for instance in [Echochamber](https://github.com/equalitie/EchoChamber), a testing platform for the (n+1)sec protocol that simulates network conditions and peer behavior to produce programmer-friendly benchmark data.


# Building (n+1)sec

## Library dependencies

The (n+1)sec library requires the following dependencies:

* cmake >= 2.8
* libgcrypt >= 1.6.0

The (n+1)sec test client, which is built by default but can be disabled, further requires the following libraries:

* libglib2
* libpurple
* libreadline

## Installing from source

The (n+1)sec library is built using cmake. To install (n+1)sec from source, run the following in the source directory:

```
$ cmake .
$ make
# make install
```


# Testing (n+1)sec

To test (n+1)sec in a graphic interface, you can install the [(n+1)sec plugin for Pidgin](https://github.com/equalitie/np1sec-test-client).

## Running the jabberite test client

The (n+1)sec library comes with a rudimentary command line chat client used to manually test the np1sec system in practice, called [_jabberite_](https://github.com/equalitie/np1sec/tree/master/test/jabberite). The jabberite tool is a basic jabber/XMPP multi-user-chat client that uses (n+1)sec for all its communications, and is built as part of the (n+1)sec test suite.

To run jabberite and connect to a given jabber multi-user chat server, run the following in the (n+1)sec build directory:
```
./jabberite --account=myusername@myserver.example.com --password=verysecret --server=conference.example.com --room=np1sec-test-room
```


## Running jabberite locally with prosody

The (n+1)sec library can be tested using the jabberite test client by running a jabber server on your local testing machine. For example, it can be run using the [_prosody_](https://prosody.im/) jabber server, configured as follows:

After installing prosody, enable the following settings in ```/etc/prosody/prosody.cfg.lua```:
```
allow_registration = true;

Component "conference.localhost" "muc"
```

Reload prosody, and create jabber user accounts for a couple of test users:
```
# prosodyctl adduser alice@localhost
# prosodyctl adduser bob@localhost
```

When this is done, a secure chat session can be set up by running multiple instances of jabberite in separate terminals:

```
$ ./jabberite --account=alice@localhost --password="alice-password" --server=conference.localhost --room=np1sec-test-room

$ ./jabberite --account=bob@localhost --password="bob-password" --server=conference.localhost --room=np1sec-test-room
```
