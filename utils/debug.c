/* filterefs - filter filesystem using regular expressions
 * Copyright (c) 2014  Jun Wu <quark@lihdd.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "debug.h"

#include <stdlib.h>
#include <sys/time.h>


#ifndef NDEBUG
int DEBUG_ENABLED = 0;
int DEBUG_PID = 0;
int DEBUG_TIMESTAMP = 0;
int DEBUG_PROGRESS = 0;
double DEBUG_START_TIME = 0;

static int read_env_bool(const char * const name, int fallback) {
  const char * const s = getenv(name);
  if (s == NULL) return fallback;
  switch (*s) {
    case 't': case 'T': case '1': case 'y': case 'Y':
      return 1;
    case 'f': case 'F': case '0': case 'n': case 'N':
      return 0;
  }
  return fallback;
}

__attribute__((constructor)) static void debug_common_init() {
  if (getenv("DEBUG") != 0) {
    DEBUG_ENABLED = 1;
    DEBUG_START_TIME = NOW;
    DEBUG_PID = read_env_bool("DEBUG_PID", 1);
    DEBUG_TIMESTAMP = read_env_bool("DEBUG_TIMESTAMP", 1);
  }
}

double now() {
  struct timeval t;
  gettimeofday(&t, 0);
  return t.tv_usec / 1e6 + t.tv_sec;
}
#endif
