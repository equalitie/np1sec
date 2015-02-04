/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "src/message.h"

/**
 * @return if the message is of type PARTICIPANTS_INFO it returns 
 *         the list of participants with their ephemerals otherwise
 *         throw an exception
 */
std::vector<UnauthenticatedParticipant> np1secMessage::participants_in_the_room()
{
  if (message_type != np1secMessageType::PARTICPANT_INFO):
    throw np1secMessageFormatException;
  
 7  int main()                                              
8  {                                                       
9      std::string str = "This is a string";               
14                                                         
15     for(auto& s: tokens)                                
16         std::cout << '"' << s << '"' << '\n';           
17 }                                                       
 

}


