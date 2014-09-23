# FORTUNE PROFILE
#
# Sets your AIM profile to a fortune (with a header and footer of your
# choice).
#

# By Sean Egan
# seanegan@gmail.com
# AIM: SeanEgn
#
# Updated by Nathan Conrad, 31 January 2002
# Changes:
#  * Fortunes have HTML tabs and newlines
# AIM: t98502
# ICQ: 16106363
#
# Updated by Mark Doliner, 15 October 2002
# Changes:
#  * Modified to work with the changed perl interface of gaim 0.60
#  * Fixed a bug where your info would be set to nothing if you had 
#    no pre and no post message
# AIM: lbdash
#
# Updated by Christian Hammond, 20 August 2003
# Changes:
#  * Modified to work with the changed perl interface of gaim 0.68
# AIM: ChipX86

# Copyright (C) 2001 Sean Egan

# This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301 USA

use Gaim;

%PLUGIN_INFO = (
	perl_api_version => 2,
	name             => "Fortune Profile",
	version          => "3.4",
	summary          => "Sets your AIM profile to a fortune (with a header and footer of your choice).",
	description      => "Sets your AIM profile to a fortune (with a header and footer of your choice).",
	author           => "Sean Egan <seanegan\@gmail.com>",
	url              => "http://pidgin.im/",

	load             => "plugin_load"
);

sub plugin_init {
	return %PLUGIN_INFO;
}

sub plugin_load {
	$plugin = shift;

	$tab = "&nbsp;";
	$tab = $tab . $tab . $tab . $tab;
	$nl = "<BR>";

	$seconds = 30;                   # Delay before updating away messages.
	$max = 1020;                     # Max length of an profile. It should be
									 # 1024, but I am being safe
	$pre_message = "";               # This gets added before the fortune

	$post_message ="";

	$len = 0;
	if ($pre_message ne "") {
	  $len += length( $pre_message . "---$nl" );
	}
	if ($post_message ne "") {
	  $len += length("---$nl" . $post_message);
	}

	# Command to get dynamic message from
	$command = "fortune -sn " . ($max - $len);

	# output the first message and start the timers...
	# This is done as a timeout to prevent attempts to set the
	# profile before logging in.
	Gaim::timeout_add($plugin, $seconds, \&update_away, 0);
}

sub update_away {
  # The fortunes are expanded into HTML (the tabs and newlines) which
  # causes the -s option of fortune to be a little bit meaningless. This
  # will loop until it gets a fortune of a good size (after expansion).

  do {
    do {  #It's a while loop because it doesn't always work for some reason
      $fortune =  `$command`;
      if ($? == -1) {
        return;
      }
    } while ($fortune eq "");
    $fortune =~ s/\n/$nl/g;
    $fortune =~ s/\t/$tab/g;
  } while ((length($fortune) + $len ) > $max);

  $message = $fortune;
  if ($pre_message ne "") {
    $message = $pre_message . "---$nl" . $message;
  }
  if ($post_message ne "") {
    $message = $message . "---$nl" . $post_message ;
  }

  foreach $account (Gaim::accounts()) {
    if ($account->is_connected()) {
      $account->set_user_info($message);
    }
  }

  Gaim::timeout_add($plugin, $seconds, \&update_away, 0);
}
