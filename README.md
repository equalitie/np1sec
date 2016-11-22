np1sec
======

Multiparty communication security implementation of the protocol described by this [paper](https://learn.equalit.ie/wiki/Np1sec)

![(n+1)sec](https://learn.equalit.ie/mw/images/7/7f/Np1sec-web.jpg)


# Building np1sec

## Library dependencies

The np1sec library requires the following dependencies:

* cmake >= 2.8
* libgcrypt >= 1.6.0

The np1sec test client, which is built by default but can be disabled, further requires the following libraries:

* libglib2
* libpurple
* libreadline

## Installing from source

The np1sec library is built using cmake. To install np1sec from source, run the following in the source directory:

```
$ cmake .
$ make
# make install
```


# Testing np1sec

## Running the jabberite test client

The np1sec library comes with a rudimentary chat client used to manually test the np1sec system in practice, called _jabberite_. The jabberite tool is a basic jabber/XMPP multi-user-chat client that uses np1sec for all its communications, and is built as part of the np1sec testsuite.

To run jabberite and connect to a given jabber multi-user-chat server, run the following in the np1sec build directory:
```
./jabberite --account=myusername@myserver.example.com --password=verysecret --server=conference.example.com --room=np1sec-test-room
```


## Running jabberite locally with prosody

The np1sec library can be tested using the jabberite test client by running a jabber server on your local testing machine. For example, it can be run using the _prosody_ jabber server, configured as follows:

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
