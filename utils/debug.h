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

#pragma once
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

extern double now();

#ifdef NDEBUG
# define PRINT_SOURCE_LOCATION ;
# define PRINT_TIMESTAMP ;
# define INFO(...) ;
#else
# define PRINT_SOURCE_LOCATION \
  if (DEBUG_ENABLED) fprintf(stderr, "  at %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
# define PRINT_TIMESTAMP { \
  if (DEBUG_TIMESTAMP) fprintf(stderr, "[%8.3f]", TIMESTAMP); \
  if (DEBUG_PID) fprintf(stderr, "[%6d] ", (int)getpid()); }
#define INFO(...) \
  if (__builtin_expect(DEBUG_ENABLED, 0)) { \
    fflush(stderr); \
    PRINT_TIMESTAMP; \
    fprintf(stderr, "INFO: "); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    fflush(stderr); }
extern double DEBUG_START_TIME;
extern int DEBUG_ENABLED;
extern int DEBUG_TIMESTAMP;
extern int DEBUG_PID;
#endif


#define NOW now()
#define TIMESTAMP (now() - DEBUG_START_TIME)
#define DEBUG_DO if (DEBUG_ENABLED)

#define FATAL(...) { \
  fflush(stderr); \
  PRINT_TIMESTAMP; \
  fprintf(stderr, "FATAL: "); \
  fprintf(stderr, __VA_ARGS__); \
  if (errno) fprintf(stderr, " (%s)", strerror(errno)); \
  fprintf(stderr, "\n"); \
  PRINT_SOURCE_LOCATION; \
  fflush(stderr); \
  exit(-1); }

#define ERROR(...) { \
  fflush(stderr); \
  PRINT_TIMESTAMP; \
  fprintf(stderr, "ERROR: "); \
  fprintf(stderr, __VA_ARGS__); \
  if (errno) fprintf(stderr, " (%s)", strerror(errno)); \
  fprintf(stderr, "\n"); \
  PRINT_SOURCE_LOCATION; \
  fflush(stderr); }

#define WARN(...) { \
  fflush(stderr); \
  PRINT_TIMESTAMP; \
  fprintf(stderr, "WARN: "); \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\n"); \
  PRINT_SOURCE_LOCATION; \
  fflush(stderr); }

