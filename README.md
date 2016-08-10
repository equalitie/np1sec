np1sec
======

Multiparty communication security implementation of the protocol described by this [paper](https://learn.equalit.ie/wiki/Np1sec)

![(n+1)sec](https://learn.equalit.ie/mw/images/7/7f/Np1sec-web.jpg)


# Building np1sec

## Library dependencies

The np1sec library requires the following libraries:

* libgcrypt >= 1.6.0

The np1sec testsuite, which for the moment is built as a mandatory component of an installation, further requires the following libraries:

* libglib2
* libevent
* libpurple
* libjsoncpp

The np1sec library is built as a GNU autotools project. To install it from source, you will need pkg-config >= 0.29. To install it from git, you will furthermore need GNU autoconf >= 2.69 and GNU automake >= 1.15.


## Installing from source

To install np1sec from a source tarball, which do not yet actually exist, run the following in the source directory:

```
$ ./configure
$ make
# make install
```


## Installing from git

To install np1sec from a git checkout, it is necessary to first build the autotools scripts by running the following in the source directory:

```
./autogen.sh
```

Afterwards, proceed to "Installing from source".


# Testing np1sec

## haveged

The np1sec testsuite uses a lot of system entropy. To ensure a sufficient supply of entropy, it is recommended to have the _haveged_ entropy daemon running during the np1sec tests, to keep the tests from taking a long time.


## Running the testsuite

After building the np1sec library (see "Installing from source"), the np1sec testsuite can be ran to verify that the library code works as expected. Running the tests should not produce any errors. The testsuite can be invoked by running ```make check```. Alternatively, it can be run in a verbose mode by invoking ```./libnp1sec_test``` instead.


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
