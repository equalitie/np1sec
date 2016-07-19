np1sec
======

[![Build Status](https://travis-ci.org/equalitie/np1sec.svg?branch=master)](https://travis-ci.org/equalitie/np1sec)

Multiparty communication security implementation of the protocol described by this [paper](https://learn.equalit.ie/wiki/Np1sec)

![(n+1)sec](https://learn.equalit.ie/mw/images/7/7f/Np1sec-web.jpg)

Debug
----
To debug with gdb

libtool --mode=execute gdb -i=mi xmpp_test

# Building
     
The following instructions describe the steps required to build np1sec from scratch on a freshly installed system running debian 8.1 stable.  It is assumed that software such as `git` and `build-essential` are already present.

```
# apt-get install git build-essential automake autoconf pkg-config libevent-dev libpurple-dev libglib2.0 glib-2.0-dev libtool


```

The following process builds all the necessary dependencies to run the np1sec executable test code.  Once built, running
the tests allows us to verify that the library code works as expected, at which point developers can use the library in
their application.  Individuals running the tests should not observe any errors.
     
Commands prefixed with `#` are to be run as root or a super user.
gThose prefixed with `$` can (should) be run as an unprivileged user.
     
## autoconf (version >= 2.69)
 
```
$ wget http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
$ tar -xzf autoconf-2.69.tar.gz
$ cd autoconf-2.69
$ ./configure
$ make
# make install
$ cd ..
```
 
## automake (version >= 1.15)
 
```
$ wget http://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz
$ tar -xzf automake-1.15.tar.gz
$ cd automake-1.15
$ ./configure
 make
# make install
$ cd ..
```

## pkg-config (version >= 0.29)

```
$ wget https://pkgconfig.freedesktop.org/releases/pkg-config-0.29.1.tar.gz
$ tar -xvf pkg-config-0.29.1.tar.gz
$ cd pkg-config-0.29.1/
$ ./configure
$ make
# make install
$ cd ..
$ export PKG_CONFIG_PATH=/usr/lib/pkgconfig/:/usr/lib/x86_64-linux-gnu/pkgconfig/
```

## libtool (version >= 2.4.6)
 
```
$ wget http://gnu.mirror.iweb.com/libtool/libtool-2.4.6.tar.gz
$ tar -xzf libtool-2.4.6.tar.gz
$ cd libtool-2.4.6
$ ./configure
$ make
# make install
$ cd ..
```
 
## libgpg-error
 
```
# apt-get install gettext 
$ gettext --version
```

If you do not have version 0.19.3 or newer, you will need to install it from
source. For example:

```
$ wget ftp.gnu.org/pub/gnu/gettext/gettext-0.19.7.tar.gz
$ tar -xzf gettext-0.19.7.tar.gz
$ cd gettext-0.19.7/
$ ./configure
$ make
# make install
```

## haveged
 
Haveged is used to generate entropy more quickly.  You may or may not want it (but you have to wait a long time to gather enough entropy if you do not install it).
 
```
# apt-get install haveged
```
 
## np1sec

Clone [np1sec](https://github.com/equalitie/np1sec).

```
$ git clone https://github.com/equalitie/np1sec
$ cd np1sec/
$ ./autogen.sh
$ ./configure
$ make
```

If configure fails complaining due to missing package check where .pc files are stored and export the path into PKG_CONFIG_PATH. For example:

```
$ export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig/
```

### Run the tests
 
```
$ ./libnp1sec_test
```

The following session tests will be run.  Session tests are responsible for ensuring that encrypted multi-party chat
sessions are conducted securely.

```
test_ression_forward_secrecy
test_cb_ack_not_received
test_cb_send_ack
test_init
test_second_join
test_solitary_talk
test_join_talk
test_three_party_chat
test_solitary_leave
test_leave_from_2p_conv
test_immature_leave_from_2p_conv
test_concurrent_join
test_concurrent_join_leave
```

```
$ ./libnp1sec_test
```

to test jabberite client

jabberite clients works with any xmpp server. Here we describe how to run prosody

```
apt-get install lua5.1 liblua5.1-expat0 lua5.1-socket lua5.1-sec lua5.1-filesystem0
cd ~/doc/code/np1sec/contrib/prosody-hg
./configure
make
```

Alternatively you can install prosody from debian repo:

```
apt-get install prosody
```

We need to edit /etc/prosody/prosody.cfg.lua and edit following lines
```
allow_registration = true;

Component "conference.localhost" "muc"
```

```
lua5.1 prosody
./prosodyctl adduser alice@localhost
./prosodyctl adduser bob@localhost

cd ../..

./jabberite --account=alice@localhost --password="" --server=conference.localhost --room=np1sectestroom
```
in another terminal

```
./jabberite --account=bob@localhost --password="" --server=conference.localhost --room=np1sectestroom
```
