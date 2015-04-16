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


#endif  // SRC_EXCEPTIONS_H_
