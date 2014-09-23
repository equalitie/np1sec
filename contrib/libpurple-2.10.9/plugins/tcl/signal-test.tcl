purple::signal connect [purple::account handle] account-away { account state message } {
	purple::debug -info "tcl signal" "account-away [purple::account username $account] \"$state\" \"$message\""
}

purple::signal connect [purple::account handle] account-connecting { account } {
	purple::debug -info "tcl signal" "account-connecting [purple::account username $account]"
}

purple::signal connect [purple::account handle] account-set-info { account info } {
	purple::debug -info "tcl signal" "account-set-info [purple::account username $account] $info"
}

purple::signal connect [purple::account handle] account-setting-info { account info } {
	purple::debug -info "tcl signal" "account-set-info [purple::account username $account] $info"
}

purple::signal connect [purple::buddy handle] buddy-away { buddy } {
	purple::debug -info "tcl signal" "buddy-away [purple::account username [lindex $buddy 2]] [lindex $buddy 1]"
}

purple::signal connect [purple::buddy handle] buddy-back { buddy } {
	purple::debug -info "tcl signal" "buddy-back [purple::account username [lindex $buddy 2]] [lindex $buddy 1]"
}

purple::signal connect [purple::buddy handle] buddy-idle { buddy } {
	purple::debug -info "tcl signal" "buddy-idle [purple::account username [lindex $buddy 2]] [lindex $buddy 1]"
}

purple::signal connect [purple::buddy handle] buddy-unidle { buddy } {
	purple::debug -info "tcl signal" "buddy-unidle [purple::account username [lindex $buddy 2]] [lindex $buddy 1]"
}

purple::signal connect [purple::buddy handle] buddy-signed-on { buddy } {
	purple::debug -info "tcl signal" "buddy-signed-on [purple::account username [lindex $buddy 2]] [lindex $buddy 1]"
}

purple::signal connect [purple::buddy handle] buddy-signed-off { buddy } {
	purple::debug -info "tcl signal" "buddy-signed-off [purple::account username [lindex $buddy 2]] [lindex $buddy 1]"
}

purple::signal connect [purple::core handle] quitting {} {
	purple::debug -info "tcl signal" "quitting"
}

purple::signal connect [purple::conversation handle] receiving-chat-msg { account who what id flags } {
	purple::debug -info "tcl signal" "receiving-chat-msg [purple::account username $account] $id $flags $who \"$what\""
	return 0
}

purple::signal connect [purple::conversation handle] receiving-im-msg { account who what id flags } {
	purple::debug -info "tcl signal" "receiving-im-msg [purple::account username $account] $id $flags $who \"$what\""
	return 0
}

purple::signal connect [purple::conversation handle] received-chat-msg { account who what id flags } {
	purple::debug -info "tcl signal" "received-chat-msg [purple::account username $account] $id $flags $who \"$what\""
}

purple::signal connect [purple::conversation handle] received-im-msg { account who what id flags } {
	purple::debug -info "tcl signal" "received-im-msg [purple::account username $account] $id $flags $who \"$what\""
}

purple::signal connect [purple::conversation handle] sending-chat-msg { account what id } {
	purple::debug -info "tcl signal" "sending-chat-msg [purple::account username $account] $id \"$what\""
	return 0
}

purple::signal connect [purple::conversation handle] sending-im-msg { account who what } {
	purple::debug -info "tcl signal" "sending-im-msg [purple::account username $account] $who \"$what\""
	return 0
}

purple::signal connect [purple::conversation handle] sent-chat-msg { account id what } {
	purple::debug -info "tcl signal" "sent-chat-msg [purple::account username $account] $id \"$what\""
}

purple::signal connect [purple::conversation handle] sent-im-msg { account who what } {
	purple::debug -info "tcl signal" "sent-im-msg [purple::account username $account] $who \"$what\""
}

purple::signal connect [purple::connection handle] signed-on { gc } {
	purple::debug -info "tcl signal" "signed-on [purple::account username [purple::connection account $gc]]"
}

purple::signal connect [purple::connection handle] signed-off { gc } {
	purple::debug -info "tcl signal" "signed-off [purple::account username [purple::connection account $gc]]"
}

purple::signal connect [purple::connection handle] signing-on { gc } {
	purple::debug -info "tcl signal" "signing-on [purple::account username [purple::connection account $gc]]"
}

if { 0 } {
purple::signal connect signing-off {
	purple::debug -info "tcl signal" "signing-off [purple::account username [purple::connection account $event::gc]]"
}

purple::signal connect update-idle {
	purple::debug -info "tcl signal" "update-idle"
}
}

purple::signal connect [purple::plugins handle] plugin-load args {
	purple::debug -info "tcl signal" "plugin-load [list $args]"
}

purple::signal connect [purple::plugins handle] plugin-unload args {
	purple::debug -info "tcl signal" "plugin-unload [list $args]"
}

purple::signal connect [purple::savedstatus handle] savedstatus-changed args {
	purple::debug -info "tcl signal" "savedstatus-changed [list $args]"
	purple::debug -info "tcl signal" "purple::savedstatus current = [purple::savedstatus current]"
}

proc plugin_init { } {
	list "Tcl Signal Test" \
             "$purple::version" \
	     "Tests Tcl signal handlers" \
             "Debugs a ridiculous amount of signal information." \
             "Ethan Blanton <elb@pidgin.im>" \
             "http://www.pidgin.im/"
}
