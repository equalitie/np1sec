$MODULE_NAME = "Signals Test Script in Perl";

use Purple;

%PLUGIN_INFO = (
	perl_api_version => 2,
	name => "Perl: $MODULE_NAME",
	version => "0.1",
	summary => "Signals Test plugin for the Perl interpreter.",
	description => "Demonstrate the use of purple signals from " .
		       "a perl plugin.",
	author => "Sadrul Habib Chowdhury <sadrul\@pidgin.im>",
	url => "http://developer.pidgin.im/wiki/sadrul/",

	load => "plugin_load",
	unload => "plugin_unload"
);

# Accounts
sub account_connecting_cb
{
	my $account = shift;
	Purple::Debug::misc("signals test in perl", "account-connecting (" . $account->get_username() . ")\n");
}

# Buddylist
sub buddy_signed_on
{
	my $buddy = shift;
	Purple::Debug::misc("signals test in perl", "buddy-signed-on (" . $buddy->get_name() . ")\n");
}

# Connections
sub signed_on
{
	my $conn = shift;
	Purple::Debug::misc("signals test in perl", "signed-on (" . $conn->get_account()->get_username() . ")\n");
}

# Conversations
sub conv_received_msg
{
	my ($account, $sender, $message, $conv, $flags, $data) = @_;
	Purple::Debug::misc("signals test in perl", "$data (" . $account->get_username() . ", $sender, $message, $flags)\n");
}

sub timeout_cb
{
	Purple::Debug::misc("signals test in perl", "timeout elapsed\n");
}

sub plugin_load
{
	my $plugin = shift;

	# Hook to the signals

	# Accounts
	$act_handle = Purple::Accounts::get_handle();
	Purple::Signal::connect($act_handle, "account-connecting", $plugin,
					\&account_connecting_cb, 0);

	# Buddy List
	$blist = Purple::BuddyList::get_handle();
	Purple::Signal::connect($blist, "buddy-signed-on", $plugin,
					\&buddy_signed_on, 0);

	# Connections
	$conn = Purple::Connections::get_handle();
	Purple::Signal::connect($conn, "signed-on", $plugin,
					\&signed_on, 0);

	# Conversations
	$conv = Purple::Conversations::get_handle();
	Purple::Signal::connect($conv, "received-im-msg", $plugin,
					\&conv_received_msg, "received im message");
	Purple::Signal::connect($conv, "received-chat-msg", $plugin,
					\&conv_received_msg, "received chat message");


	Purple::timeout_add($plugin, 10, \&timeout_cb);
}

sub plugin_unload
{
	# Nothing to do here for this plugin.
}

