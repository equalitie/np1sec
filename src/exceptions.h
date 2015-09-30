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

namespace np1sec
{

class SessionStateException : public std::exception
{
    virtual const char* what() const throw() { return "Invalid session state"; }
};

class MessageFormatException : public std::exception
{
    virtual const char* what() const throw() { return "Invalid message format"; }
};

class VersionMismatchException : public std::exception
{
    virtual const char* what() const throw() { return "Invalid protocol version"; }
};

class MessageSignatureException : public std::exception
{
    virtual const char* what() const throw() { return "Signature failed verification"; }
};

class CryptoException : public std::exception
{
    virtual const char* what() const throw() { return "Crypto error"; }
};

class InsufficientCredentialException : public std::exception
{
    virtual const char* what() const throw() { return "Insufficient credentials"; }
};

class AuthenticationException : public std::exception
{
    virtual const char* what() const throw() { return "Authentication failure"; }
};

class InvalidDataException : public std::exception
{
    virtual const char* what() const throw() { return "Data doesn't match expected value"; }
};

class InvalidRoomException : public std::exception
{
    virtual const char* what() const throw() { return "Invalid room"; }
};

class InvalidSessionStateException : public std::exception
{
    virtual const char* what() const throw() { return "Invalid session state"; }
};

class DoubleJoinException : public std::exception
{
    virtual const char* what() const throw() { return "A nickname tried to join a room twice"; }
};

class InvalidParticipantException : public std::exception
{
    virtual const char* what() const throw() { return "Invalid Participant"; }
};

class NotImplementedException : public std::exception
{
    virtual const char* what() const throw() { return "Not Implemented"; }
};

} // namespace np1sec

#endif // SRC_EXCEPTIONS_H_
