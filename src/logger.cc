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

#include "src/logger.h"

// Standard constructor
// Threshold adopts a default level of DEBUG if an invalid threshold is provided.
Logger::Logger(log_level_t threshold)
{
  if (threshold < SILLY || threshold > ERROR) {
    this->threshold = default_log_level;
  } else {
    this->threshold = threshold;
  }
  log_to_stdout = true;
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

// Configure the logger to log to stdout and/or to a file.
void Logger::config(bool log_stdout, bool log_to_file, std::string fname)
{
  log_to_stdout = log_stdout;
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
  if (level >= SILLY && level <= ERROR) {
    threshold = level;
  }
}

// Standard log function. Prints nice colors for each level.
void Logger::log(log_level_t level, std::string msg)
{
  if (level < SILLY || level > ERROR || level < threshold) {
    return;
  }
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
  }
  if (log_to_stdout) {
    std::cout << msg << std::endl;
  }
  if (log_to_file && log_file.is_open()) {
    log_file << msg << std::endl;
  }
}

// Convenience methods

void Logger::silly(std::string msg)
{
  log(SILLY, msg);
}

void Logger::debug(std::string msg)
{
  log(DEBUG, msg);
}

void Logger::verbose(std::string msg)
{
  log(VERBOSE, msg);
}

void Logger::info(std::string msg)
{
  log(INFO, msg);
}

void Logger::warn(std::string msg)
{
  log(WARN, msg);
}

void Logger::error(std::string msg)
{
  log(ERROR, msg);
}
