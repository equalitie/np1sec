#!/usr/bin/env python
#
# Makes sure only one purple instance is running
#
# Purple is the legal property of its developers, whose names are too numerous
# to list here.  Please refer to the COPYRIGHT file distributed with this
# source distribution.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
#

from __future__ import print_function
import sys
import dbus
import os

if len(sys.argv) == 1:
    print("Usage:", sys.argv[0], "<purple-client> [arguments]")
    print("\nExample:\n   ", sys.argv[0], "pidgin -d -c /my/home")
    sys.exit(1)

home = os.path.expanduser('~/.purple/')
for arg in range(1, len(sys.argv[1:])):
	if sys.argv[arg] == "-c":
		home = os.path.expanduser(sys.argv[arg + 1])
		break

bus = dbus.SessionBus()

try:
	obj = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
	purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
	userdir = purple.PurpleUserDir()
	if not os.path.isabs(userdir):
		userdir = os.path.join(purple.PurpleHomeDir(), userdir)
	if home == userdir:
		print("Already running.")
		purple.PurpleBlistShow()
	else:
		print("Starting client from a different home directory.")
		raise
except:
	os.execlp(sys.argv[1], " ".join(sys.argv[2:]))
