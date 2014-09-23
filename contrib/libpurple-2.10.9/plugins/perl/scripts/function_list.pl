$MODULE_NAME = "List all Purple:: (and Pidgin::) functions";
use Purple;
# Uncomment this to print the Pidgin:: functions as well.
#use Pidgin;

# All the information Purple gets about our nifty plugin
%PLUGIN_INFO = (
	perl_api_version => 2,
	name             => "Perl: $MODULE_NAME",
	version          => "0.1",
	summary          => "Print to standard output all the functions under the Purple:: (and Pidgin::) packages",
	description      => "Print to standard output all the functions under the Purple:: (and Pidgin::) packages",
	author           => "Etan Reisner <deryni\@gmail.com>",
	url              => "http://sourceforge.net/users/deryni9/",
	id               => "functionlist",

	load             => "plugin_load",
	unload           => "plugin_unload"
);

sub plugin_init {
	return %PLUGIN_INFO;
}

sub print_array {
	my $array = shift;

	my @arr = sort @$array;
	foreach $mod (@arr) {
		my @sub;

		foreach $key (sort keys %{$mod}) {
			if ($key =~ /::$/) {
				push @sub, "$mod$key";
			} else {
				print "$mod$key\n";
			}
		}
		print_array(\@sub);
	}
}

sub plugin_load {
	my $plugin = shift;
	my @purplearray;
	my @pidginarray;

	foreach $key (sort keys %Purple::) {
		if ($key =~ /::$/) {
			push @purplearray, "Purple::$key";
		} else {
			print "Purple::$key\n";
		}
	}
	print_array(\@purplearray);

	foreach $key (sort keys %Pidgin::) {
		if ($key =~ /::$/) {
			push @pidginarray, "Pidgin::$key";
		} else {
			print "Pidgin::$key\n";
		}
	}
	print_array(\@pidginarray);
}

sub plugin_unload {
	my $plugin = shift;
}
