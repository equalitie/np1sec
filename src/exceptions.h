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

#ifndef SRC_EXCEPTIONS_H_
#define SRC_EXCEPTIONS_H_

#include <exception>

namespace np1sec {

class np1secSessionStateException: public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Invalid session state";                               
   }
};

class np1secMessageFormatException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Invalid message format";                               
   }                                                               
 };                                   

class np1secVersionMismatchException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Invalid protocol version";                               
   }                                                               
 };                                   

class np1secMessageSignatureException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Signature failed verification";                               
   }                                                               
 };                                   


class np1secCryptoException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Crypto error";                               
   }                                                               
};                                   

class np1secInsufficientCredentialException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Insufficient credentials";                               
   }                                                               
 };                                   

class np1secAuthenticationException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Authentication failure";                               
   }                                                               
};                                   

class np1secInvalidDataException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Data doesn't match expected value";                               
   }                                                               
 };                                   

class np1secInvalidRoomException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Invalid room";                               
   }                                                               
 };                                   

class np1secInvalidSessionStateException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Invalid session state";                               
   }                                                               
 };                                   

class np1secDoubleJoinException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "A nickname tried to join a room twice";                               
   }                                                               
};                                   

class np1secInvalidParticipantException : public std::exception                               
{                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Invalid Participant";                               
   }                                                               
};                                   

class np1secNotImplementedException : public std::exception                             {                                                                 
   virtual const char* what() const throw()                        
   {                                                               
     return "Not Implemented";                               
   }                                                               
 };

} // namespace np1sec

#endif  // SRC_EXCEPTIONS_H_
