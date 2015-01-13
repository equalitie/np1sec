/**
   This is a mock/simulator of a multi party chat protocol runing on the
   same machine for the purpose of testing np1sec 

   Authors: Vmon, 2015-01: initial version
 */

#include <map>
#include <vector>

#ifndef CHAT_MONCKER_H
#def CHAT_MOCKER_H
/**
   This class store the information about different participants
   including their receive and send functions 
 */

class mock_participant
{
 public:
  std::string nick;
  void (*receive_handler)(std::string room_name, std::string message);

}

class mock_room
{
 public:
  std::string room;
  std::map<std::string, mock_participant> participant_list;

  join(std::string nick);
  
};  

/**
   This client simulate both client and server.
   as everythnig happens locally
 */
class ChatMocker
{
 protected:
  std::map<std::string,> rooms;
  std::map<std::string, mock_participant> signed_in_participant;
  
 public:
  /**
   * Add the participant to the singed in list and keep track of their
   * receive handler 
   */
  void sign_in(std::string nick, void (*receive_handler)(std::string room_name, std::string message))
  {
    signed_in_participant[nick].receive_handler = receive_handler;
    
  };
  
  /**
   * join the room by adding the name of the participant to the room list
   */
  void join(std::string room, std::string nick);
  {
    rooms[room].join(nick);
  
  };

  /**
     return the list of participant in the room
     it makes the base for the list of participant in the room
   */
  std::vector<std::string> participant_list(std::string room)
  {
    return rooms[room].participant_list();
  };

  /**
   * drop the participant from the room
   */
  void leave(std::string room, std::string nick);
  {
    rooms[room].leave(nick);
  
  };
  
  /**
   * drop the participant from the room
   */
  void send(std::string room, std::string nick, std::string message)
  {
    rooms[room].send(nick, message);
  }

};

#endif
