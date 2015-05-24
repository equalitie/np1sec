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

#ifndef SRC_LOGGER_H_
#define SRC_LOGGER_H_

// Standard log levels, ascending order of specificity.
enum log_level_t {
  SILLY,
  DEBUG,
  VERBOSE,
  INFO,
  WARN,
  ERROR,
  ABORT
};

const log_level_t default_log_level = DEBUG;

class Logger {
protected:
  log_level_t threshold;
  bool log_to_stdout;
  bool log_to_file;
  std::string log_filename;
  std::ofstream log_file;

public:
  // Constructor sets an initial threshold
  Logger(log_level_t threshold);
  // Destructor closes an open log file
  ~Logger();

  // Get the current log file name
  std::string current_log_file() { return log_filename; }

  void config(bool log_stdout, bool log_file, std::string fname);
  void set_threshold(log_level_t level);
  void log(log_level_t level, std::string msg);
  void silly(std::string msg);
  void debug(std::string msg);
  void verbose(std::string msg);
  void info(std::string msg);
  void warn(std::string msg);
  void error(std::string msg);
  void abort(std::string msg);
  
  void assert(bool expr, std::string failure_message);
  
};

#endif  // SRC_LOGGER_H_
