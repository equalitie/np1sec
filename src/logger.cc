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

#include <iostream>
#include <fstream>

#include "logger.h"

#include "session.h"
#include "message.h"

namespace np1sec
{

Logger logger(DEBUG);

void Logger::initiate_textual_conversions()
{
    state_to_text[Session::NONE] = "NONE";
    state_to_text[Session::JOIN_REQUESTED] = "JOIN_REQUESTED";
    state_to_text[Session::RE_SHARED] = "RE_SHARED";
    state_to_text[Session::GROUP_KEY_GENERATED] = "GROUP_KEY_GENERATED";
    state_to_text[Session::IN_SESSION] = "IN_SESSION";
    state_to_text[Session::LEAVE_REQUESTED] = "LEAVE_REQUESTED";
    state_to_text[Session::STALE] = "STALE";
    state_to_text[Session::DEAD] = "DEAD";

    message_type_to_text[Message::JOIN_REQUEST] = "JOIN_REQUEST";
    message_type_to_text[Message::PARTICIPANTS_INFO] = "PARTICIPANTS_INFO";
    message_type_to_text[Message::JOINER_AUTH] = "JOINER_AUTH";
    message_type_to_text[Message::GROUP_SHARE] = "GROUP_SHARE";
    message_type_to_text[Message::SESSION_CONFIRMATION] = "SESSION_CONFIRMATION";
}

// Standard constructor
// Threshold adopts a default level of DEBUG if an invalid threshold is provided.
Logger::Logger(log_level_t threshold)
{
    initiate_textual_conversions();

    if (threshold < SILLY || threshold > ERROR) {
        this->threshold = default_log_level;
    } else {
        this->threshold = threshold;
    }
    log_to_stderr = true;
    log_to_file = false;
    log_filename = "";
}

// Standard destructor
Logger::~Logger()
{
    if (log_file.is_open()) {
        log_file.close();
    }
}

// Configure the logger to log to stderr and/or to a file.
void Logger::config(bool log_stderr, bool log_to_file, std::string fname)
{
    log_to_stderr = log_stderr;
    this->log_to_file = log_to_file;
    if (log_to_file) {
        log_filename = fname;
        log_file.open(log_filename, std::ios::out | std::ios::app);
    } else {
        if (log_file.is_open()) {
            log_file.close();
        }
    }
}

// Update the logger's threshold.
// If an invalid level is provided, do not update.
void Logger::set_threshold(log_level_t level)
{
    if (level >= SILLY && level <= ABORT) {
        threshold = level;
    }
}

// Standard log function. Prints nice colors for each level.
void Logger::log(log_level_t level, std::string msg, std::string function_name, std::string user_nick)
{
    if (level < SILLY || level > ABORT || level < threshold) {
        return;
    }

    msg = (user_nick.empty()) ? msg : user_nick + ": " + msg;
    msg = (function_name.empty()) ? msg : function_name + ": " + msg;

    switch (level) {
    case SILLY:
        msg = "\033[1;35;47m[SILLY] " + msg + "\033[0m";
        break;
    case DEBUG:
        msg = "\033[1;32m[DEBUG]\033[0m " + msg;
        break;
    case VERBOSE:
        msg = "\033[1;37m[VERBOSE]\033[0m " + msg;
        break;
    case INFO:
        msg = "\033[1;34m[INFO]\033[0m " + msg;
        break;
    case WARN:
        msg = "\033[90;103m[WARN] " + msg + "\033[0m";
        break;
    case ERROR:
        msg = "\033[91;40m[ERROR] " + msg + "\033[0m";
        break;
    case ABORT:
        msg = "\033[91;40m[ABORT] " + msg + "\033[0m";
        break;
    }
    if (log_to_stderr) {
        std::cerr << msg << std::endl;
    }
    if (log_to_file && log_file.is_open()) {
        log_file << msg << std::endl;
    }
}

// Convenience methods

void Logger::silly(std::string msg, std::string function_name, std::string user_nick)
{
    log(SILLY, msg, function_name, user_nick);
}

void Logger::debug(std::string msg, std::string function_name, std::string user_nick)
{
    log(DEBUG, msg, function_name, user_nick);
}

void Logger::verbose(std::string msg, std::string function_name, std::string user_nick)
{
    log(VERBOSE, msg, function_name, user_nick);
}

void Logger::info(std::string msg, std::string function_name, std::string user_nick)
{
    log(INFO, msg, function_name, user_nick);
}

void Logger::warn(std::string msg, std::string function_name, std::string user_nick)
{
    log(WARN, msg, function_name, user_nick);
}

void Logger::error(std::string msg, std::string function_name, std::string user_nick)
{
    log(ERROR, msg, function_name, user_nick);
}

void Logger::abort(std::string msg, std::string function_name, std::string user_nick)
{
    log(ABORT, msg, function_name, user_nick);
    exit(1);
}

void Logger::assert_or_die(bool expr, std::string failure_message, std::string function_name, std::string user_nick)
{
    if (!expr)
        abort(failure_message, function_name, user_nick);
}

} // namespace np1sec
