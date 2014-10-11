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

#include <stdio.h>
#include <regex.h>

struct frefs_config {
  regex_t read_white_re;
  regex_t read_black_re;
  regex_t write_white_re;
  regex_t write_black_re;
  int read_re_enabled;
  int write_re_enabled;
};

typedef struct frefs_config frefs_config_t;

extern const int FREFS_PERM_READ;
extern const int FREFS_PERM_WRITE;


/**
 * Initialize frefs_config_t by reading read-only and read-write config files.
 * The config files are like .gitignore, but uses regular expressions.
 * - blank lines and lines start with '#' are ignored
 * - lines start with '!' are blacklist
 * - remaining lines are whitelist
 *
 * A valid config example:
 *
 * /dev(/(full|null|urandom|random|zero))?
 * /(lib|lib64|usr|bin|tmp|etc|proc)(/.*)?
 * !/proc/1(/.*)?
 *
 * @param  pconfig         pointer to the frefs_config_t struct, which will be written
 * @param  read_filepath   readable config file path
 * @param  write_filepath  writable config file path
 * @return  0              success
 *         -1              can not open the file
 *         -2              can not compile the regular expressions
 */
int frefs_config_import(frefs_config_t *pconfig, const char *read_filepath, const char *write_filepath);


/**
 * Check file permission against frefs_config_t.
 *
 * @param  pconfig      pointer to the frefs_config_t struct, which was initialized by
 *                      frefs_config_import
 * @param  path         full, absolute file path to check. should be expaned (i.e. no "..")
 * @param  permission   permission(s) to check. FREFS_PERM_READ or FREFS_PERM_WRITE or their sum
 * @return 0            permission rejected
 *         other        some permission accepted: one of FREFS_PERM_READ, FREFS_PERM_WRITE; or
 *                      their sum, which means both read and write permissions
 */
int frefs_config_get_file_permission(frefs_config_t *pconfig, const char *path, int permission);


/**
 * Release internal allocated memory.
 *
 * @param  pconfig      pointer to an initialized frefs_config_t struct
 */
void frefs_config_free(frefs_config_t *pconfig);
