#ifndef jabberling_h
#define jabberling_h

#include <string>
#include <vector>

struct Jabberite;
#define UNUSED(x) ((void)(x))

int jabberling_main(int argc, char **argv);
void jabberling_send(struct Jabberite* settings, std::string message);
void jabberling_print(std::string message);

void ui_connection_error(std::string message);
void ui_connected(struct Jabberite* settings, std::string username, std::vector<std::string> users);
void ui_joined(struct Jabberite* settings, std::string username);
void ui_left(struct Jabberite* settings, std::string username);
void ui_message(struct Jabberite* settings, std::string username, std::string message);

void ui_input(struct Jabberite* settings, std::string line);

#endif
