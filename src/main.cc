#include "jabberling.h"
#include "interface.h"
#include "room.h"

extern "C" {
#include "glib.h"
}

class JabberlingChannelInterface final : public np1sec::ChannelInterface
{
	public:
	JabberlingChannelInterface(np1sec::Channel* channel): m_channel(channel) {}
	
	void user_joined(const std::string& username);
	void user_left(const std::string& username);
	void user_authenticated(const std::string& username, const np1sec::PublicKey& public_key);
	void user_authentication_failed(const std::string& username);
	void user_authorized_by(const std::string& user, std::string target);
	void user_promoted(const std::string& username);
	void joined();
	void authorized();
	
	void dump();
	
	public:
	np1sec::Channel* m_channel;
};

class JabberlingRoomInterface : public np1sec::RoomInterface
{
	public:
	JabberlingRoomInterface(Jabberite* settings): m_settings(settings) {}
	
	void send_message(const std::string& message);
	np1sec::TimerToken* set_timer(uint32_t interval, np1sec::TimerCallback* callback);
	
	np1sec::ChannelInterface* new_channel(np1sec::Channel* channel);
	void channel_removed(np1sec::Channel* channel);
	void joined_channel(np1sec::Channel* channel);
	void disconnected();
	
	protected:
	struct Jabberite* m_settings;
};

JabberlingRoomInterface* global_interface = 0;
std::string global_username;
np1sec::Room* global_room = 0;
std::vector<JabberlingChannelInterface*> global_channels;

static std::string fingerprint(np1sec::PublicKey public_key)
{
	std::string output;
	for (size_t i = 0; i < sizeof(public_key.buffer); i++) {
		if (i > 0) {
			output += ':';
		}
		output += "0123456789abcdef"[(public_key.buffer[i] >> 4) & 0x0f];
		output += "0123456789abcdef"[(public_key.buffer[i] >> 0) & 0x0f];
	}
	return output;
}




void ui_connection_error(std::string message)
{
	jabberling_print("* Connection error: " + message + "\n");
}

void ui_connected(struct Jabberite* settings, std::string username, std::vector<std::string> users)
{
	UNUSED(users);
	
	global_interface = new JabberlingRoomInterface(settings);
	global_username = username;
	
	jabberling_print("* Connected as " + username + "\n");
}

void ui_joined(struct Jabberite* settings, std::string username)
{
	UNUSED(settings);
	
	jabberling_print("* " + username + " joined the room\n");
}

void ui_left(struct Jabberite* settings, std::string username)
{
	UNUSED(settings);
	
	jabberling_print("* " + username + " left the room\n");
	
	if (global_room) {
		global_room->user_left(username);
	}
}

void ui_message(struct Jabberite* settings, std::string username, std::string message)
{
	UNUSED(settings);
	
	if (global_room) {
		global_room->message_received(username, message);
	}
}



void JabberlingRoomInterface::send_message(const std::string& message)
{
	jabberling_send(m_settings, message);
}

struct Np1secTimer final : public np1sec::TimerToken
{
	np1sec::TimerCallback* callback;
	guint timer_id;
	
	void unset()
	{
		g_source_remove(timer_id);
		delete this;
	}
};

static gboolean execute_timer(gpointer np1sec_timer)
{
	Np1secTimer* timer = reinterpret_cast<Np1secTimer*>(np1sec_timer);
	timer->callback->execute();
	delete timer;
	// returning 0 stops the timer
	return 0;
}

np1sec::TimerToken* JabberlingRoomInterface::set_timer(uint32_t interval, np1sec::TimerCallback* callback)
{
	Np1secTimer* timer = new Np1secTimer;
	timer->callback = callback;
	timer->timer_id = g_timeout_add(interval, execute_timer, timer);
	return timer;
}



np1sec::ChannelInterface* JabberlingRoomInterface::new_channel(np1sec::Channel* channel)
{
	JabberlingChannelInterface* interface = new JabberlingChannelInterface(channel);
	int id = global_channels.size();
	global_channels.push_back(interface);
	
	jabberling_print("** Found channel " + std::to_string(id) + ":\n");
	interface->dump();
	
	return interface;
}

void JabberlingRoomInterface::channel_removed(np1sec::Channel* channel)
{
	for (size_t i = 0; i < global_channels.size(); i++) {
		if (global_channels[i] && global_channels[i]->m_channel == channel) {
			jabberling_print("** Removing channel " + std::to_string(i) + ":\n");
			global_channels[i]->dump();
			
			delete global_channels[i];
			global_channels[i] = nullptr;
		}
	}
}

void JabberlingRoomInterface::joined_channel(np1sec::Channel* channel)
{
	for (size_t i = 0; i < global_channels.size(); i++) {
		if (global_channels[i]) {
			if (global_channels[i]->m_channel == channel) {
				jabberling_print("** Joined channel " + std::to_string(i) + ":\n");
				global_channels[i]->dump();
			} else {
				delete global_channels[i];
				global_channels[i] = nullptr;
			}
		}
	}
}

void JabberlingRoomInterface::disconnected()
{
	jabberling_print("*** disconnected\n");
}



void JabberlingChannelInterface::user_joined(const std::string& username)
{
	jabberling_print("** User " + username + " joined the channel\n");
	dump();
}

void JabberlingChannelInterface::user_left(const std::string& username)
{
	jabberling_print("** User " + username + " left the channel\n");
	dump();
}

void JabberlingChannelInterface::user_authenticated(const std::string& username, const np1sec::PublicKey& public_key)
{
	jabberling_print("** User " + username + " authenticated as " + public_key.dump_hex() + "\n");
	dump();
}

void JabberlingChannelInterface::user_authentication_failed(const std::string& username)
{
	jabberling_print("** User " + username + " failed authentication\n");
	dump();
}

void JabberlingChannelInterface::user_authorized_by(const std::string& user, std::string target)
{
	jabberling_print("** User " + target + " was authorized by " + user + "\n");
	dump();
}

void JabberlingChannelInterface::user_promoted(const std::string& username)
{
	jabberling_print("** User " + username + " was promoted\n");
	dump();
}

void JabberlingChannelInterface::joined()
{
	jabberling_print("** You joined the channel\n");
	dump();
}

void JabberlingChannelInterface::authorized()
{
	jabberling_print("** You were promoted\n");
	dump();
}

void JabberlingChannelInterface::dump()
{
	jabberling_print(std::string("Channel status:\n"));
	jabberling_print(std::string("  Member: ") + (m_channel->am_member() ? "yes" : "no") + "\n");
	jabberling_print(std::string("  Authorized: ") + (m_channel->am_authorized() ? "yes" : "no") + "\n");
	jabberling_print(std::string("Participants:\n"));
	for (const std::string& username : m_channel->users()) {
		jabberling_print(std::string("  ") + username + "\n");
		if (m_channel->user_authentication(username) == np1sec::Channel::AuthenticationStatus::Authenticated) {
			jabberling_print(std::string("    Identity: ") + m_channel->user_key(username).dump_hex() + "\n");
		} else if (m_channel->user_authentication(username) == np1sec::Channel::AuthenticationStatus::AuthenticationFailed) {
			jabberling_print(std::string("    Identity: FAILED\n"));
		} else {
			jabberling_print(std::string("    Identity: Unauthenticated\n"));
		}
		jabberling_print(std::string("    Authorized: ") + (m_channel->user_is_authorized(username) ? "yes" : "no") + "\n");
		if (!m_channel->user_is_authorized(username)) {
			for (const std::string& peer : m_channel->users()) {
				if (m_channel->user_is_authorized(peer)) {
					jabberling_print(std::string("      ") + peer + ":\n");
					jabberling_print(std::string("        ") + username + " authorized by " + peer + ": " + (m_channel->user_has_authorized(peer, username) ? "yes" : "no") + "\n");
					jabberling_print(std::string("        ") + peer + " authorized by " + username + ": " + (m_channel->user_has_authorized(username, peer) ? "yes" : "no") + "\n");
				}
			}
		}
	}
}




void ui_input(struct Jabberite* settings, std::string line)
{
	UNUSED(settings);
	
	if (line == "/connect") {
		if (global_room) {
			delete global_room;
		}
		
		np1sec::PrivateKey private_key = np1sec::PrivateKey::generate();
		jabberling_print("*** Joining the room as " + global_username + "::" + fingerprint(private_key.public_key()) + "\n");
		
		global_room = new np1sec::Room(global_interface, global_username, private_key);
		global_room->join_room();
		global_room->search_channels();
	} else if (line == "/create") {
		global_room->create_channel();
	} else if (line.substr(0, 5) == "/join") {
		size_t id = std::stoi(line.substr(6));
		if (id < global_channels.size() && global_channels[id]) {
			jabberling_print("*** Joining channel " + std::to_string(id) + "\n");
			global_room->join_channel(global_channels[id]->m_channel);
		}
	} else if (line.substr(0, 7) == "/accept") {
		global_room->authorize(line.substr(8));
	}
}

int main(int argc, char** argv)
{
	jabberling_main(argc, argv);
}
