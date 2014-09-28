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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <stdlib.h>
#include "utils/str_append.h"
#include "utils/debug.h"
#include "config.h"


const int FREFS_PERM_READ = 1;
const int FREFS_PERM_WRITE = 2;


static int frefs_config_build_regex_from_file(const char *filepath, regex_t *pwhite_re, regex_t *pblack_re) {
  int result = 0;
# define str_define(name, init_size) \
  char *name = NULL; \
  size_t name ## _size = init_size;
# define re_define(name) \
  str_define(name, 1); \
  str_append(name, "^(");
# define re_add_line(name, line) \
  if (line && *line != 0) { \
    int first = name ## _size <= 3; \
    str_append(name, (first ?  "(" : "|(")); \
    str_append(name, (line)); \
    str_append(name, ")"); }
# define re_compile(name, out) { \
  int ret = regcomp(out, name, REG_EXTENDED | REG_NOSUB); \
  if (ret) {\
    char error_buf[120]; \
    error_buf[0] = 0; \
    regerror(ret, out, error_buf, sizeof(error_buf)); \
    WARN("can not compile regex %s: \"%s\" (%d: %s)", #name, name, ret, error_buf); \
    result = -2; \
    goto cleanup; } }

  re_define(white_str);
  re_define(black_str);
  str_define(line_buf, 0);
  FILE *fp = NULL;

  if (filepath) {
    fp = fopen(filepath, "r");
    if (!fp) {
      WARN("can not open file: %s", filepath);
      result = -1;
      goto cleanup;
    }

    while (!feof(fp)) {
      int line_len = getline(&line_buf, &line_buf_size, fp);

      if (line_len < 0) break;
      if (line_len <= 1) continue;
      if (line_buf[0] == '#') continue;

      line_buf[line_len - 1] = 0;  // chomp

      if (line_buf[0] == '!') {  // blacklist
        re_add_line(black_str, line_buf + 1);
      } else {  // whitelist
        re_add_line(white_str, line_buf);
      }
    }
  }

  str_append(white_str, ")$");
  str_append(black_str, ")$");

  INFO("%s whitelist re: %s", filepath, white_str);
  INFO("%s blacklist re: %s", filepath, black_str);

  re_compile(white_str, pwhite_re);
  re_compile(black_str, pblack_re);

cleanup:
  if (white_str) free(white_str);
  if (black_str) free(black_str);
  if (line_buf) free(line_buf);
  if (fp) fclose(fp);
  return result;
# undef re_compile
# undef re_define
# undef str_define
}


int frefs_config_import(frefs_config_t *pconfig, const char *read_filepath, const char *write_filepath) {
  // the config files are like gitignore, but uses regexp
  // lines start with '!' are blacklist
  // lines start with '#' are comments
  int ret = 0;
  ret = frefs_config_build_regex_from_file(read_filepath, &(pconfig->read_white_re), &(pconfig->read_black_re));
  if (ret) return ret;

  ret = frefs_config_build_regex_from_file(write_filepath, &(pconfig->write_white_re), &(pconfig->write_black_re));
  return ret;
}

int frefs_config_get_file_permission(frefs_config_t *pconfig, const char *path, int permission) {
  int result = 0;
# define re_match(re, str) (regexec(&(re), (str), 0, NULL, 0) == 0)
# define re_check_permission(name, str) \
  (!re_match(pconfig->name ## _black_re, str) && re_match(pconfig->name ## _white_re, str))

  if (path && path[0] == '/' && path[1] == 0) {
    // always allow read '/'
    result |= FREFS_PERM_READ;
  }

  if (pconfig) {
    // check write
    if (permission & FREFS_PERM_WRITE) {
      if (re_check_permission(write, path)) result |= FREFS_PERM_WRITE;
    } 
    // check read
    if (((permission & FREFS_PERM_READ) != 0) && ((result & FREFS_PERM_READ) == 0)) {
      if (re_check_permission(read, path)) result |= FREFS_PERM_READ;
    }
  }
  INFO("frefs_config_get_file_permission(\"%s\", %d) = %d", path, permission, result);
  return result;
# undef re_match
# undef re_check_permission
}

void frefs_config_free(frefs_config_t *pconfig) {
  if (!pconfig) return;
# define re_dual_free(prefix) \
  regfree(&pconfig->prefix ## _white_re); \
  regfree(&pconfig->prefix ## _black_re);
  re_dual_free(read);
  re_dual_free(write);
# undef re_dual_free
}
