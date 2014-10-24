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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* append a string. requires <strname>_size defined for perf reason. ex:
 *
 * char *str = NULL;
 * size_t str_size = 1;
 *
 * str_append(str, "abcd");  // str becomes "abcd" and str_size becomes 5.
 * str_append(str, "!!!");   // str becomes "abcd!!!" and str_size becomes 8.
 */
#define str_append(name, str) { \
  assert(name ## _size >= 1); \
  int len = strlen(str); \
  name ## _size += len; \
  char *new_name = realloc(name, name ## _size); \
  if (new_name) name = new_name; else /* realloc failed */ abort(); \
  char *curr_pos = name + (name ## _size) - 1 - len; \
  strncpy(curr_pos, str, name ## _size - (curr_pos - name)); }
