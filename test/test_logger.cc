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

/* This test provides example usage for the logger */

#include "contrib/gtest/include/gtest/gtest.h"
#include "src/logger.h"

class LoggerTest : public ::testing::Test {};

TEST_F(LoggerTest, test_logging) {
  Logger log(SILLY); // All logs with level >= SILLY will display
  log.config(true, true, "testlog.txt"); // Log to stdout and file testlog.txt

  // Do some logging
  // You can call log with a level manually
  log.log(INFO, "This is the first info log");
  log.log(SILLY, "This is the first silly log");
  // Or you can use a convenience method, named after the log level
  log.warn("This is the first warning");
  log.error("This is the first error");

  // Set the log threshold to something higher.
  // Now we will only see logs with a level >= VERBOSE
  log.set_threshold(VERBOSE);
  log.verbose("This should make it out");
  log.warn("This should make it out");
  log.debug("This should not make it out");
  log.silly("This should not make it out");

  // Stop writing to a file.
  log.config(true, false, "");
  log.info("This should not make it to the file.");

  // Stop outputting logs at all.
  log.config(false, false, "");
  log.error("This should not make it out");
}
