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
 *
 *
 * This file takes a lot of code from fusexmp.c shipped with fuse.
 * fusexmp.c is covered by the following copyright and permission notice:
 *
 *   fusexmp.c - FUSE: Filesystem in Userspace
 *
 *   Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *   Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>
 *   This program can be distributed under the terms of the GNU GPL.
 *   See the file COPYING.
 */

#define _GNU_SOURCE

#define FUSE_USE_VERSION 26

#ifndef FREFS_GIT_VERSION
# define FREFS_GIT_VERSION ""
#endif
#define FREFS_VERSION (sizeof(FREFS_GIT_VERSION) > 1 ? FREFS_GIT_VERSION : "v0.1")

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <unistd.h>
#include <fuse.h>

#include <linux/limits.h>

#include "config.h"
#include "utils/debug.h"


// configuration
static char *readable_config_path = NULL;
static char *writable_config_path = NULL;
static char *dest = NULL;

static frefs_config_t config;


#define ensure_read_perm(path) \
  if (!frefs_config_get_file_permission(&config, path, FREFS_PERM_READ)) { return -EPERM; }
#define ensure_write_perm(path) \
  if (!frefs_config_get_file_permission(&config, path, FREFS_PERM_WRITE)) { return -EPERM; }
#define return_checked(exp) \
  { int _ret = (exp); return _ret == -1 ? -errno : _ret; }
#define return_checked_zero(exp) \
  { int _ret = (exp); return _ret == -1 ? -errno : 0; }


static const char *path_join(const char *dirname, const char *basename) {
  static char *result = NULL;
  static size_t last_size = 0;

  if (!dirname || dirname[0] == 0) return basename;

  int dir_len = strlen(dirname);
  int base_len = strlen(basename);
  size_t size = dir_len + base_len + 2;

  if (size > last_size) {
    result = realloc(result, dir_len + base_len + 2);
    last_size = size;
  }

  strcpy(result, dirname);

  // check '/'
  int offset = 1;
  if (dir_len > 0 && dirname[dir_len - 1] == '/') --offset;
  if (base_len > 0 && basename[0] == '/') --offset;
  if (offset > 0) result[dir_len] = '/';
  strcpy(result + dir_len + offset, basename);

  return result;
}


static int frefs_getattr(const char *path, struct stat *st_data) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  return_checked_zero(lstat(path, st_data));
}

static int frefs_readlink(const char *path, char *buf, size_t size) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  int res = readlink(path, buf, size - 1);
  if (res == -1) { return -errno; }
  buf[res] = '\0';
  return 0;
}

static int frefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,off_t offset, struct fuse_file_info *fi) {
  DIR *dp;
  struct dirent *de;

  (void) offset;
  (void) fi;

  INFO("%s %s", __func__, path);
  ensure_read_perm(path);

  dp = opendir(path);
  if (dp == NULL) { return -errno; }

  while ((de = readdir(dp)) != NULL) {
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino = de->d_ino;
    st.st_mode = de->d_type << 12;

    int len = strlen(de->d_name);
    if (len <= 2 && (de->d_name[0] == '.' && (len == 1 || de->d_name[1] == '.'))) {
      // it's '.' and '..', pass
    } else {
      // hide filtered entities
      if (!frefs_config_get_file_permission(&config, path_join(path, de->d_name), FREFS_PERM_READ)) continue;
    }
    if (filler(buf, de->d_name, &st, 0)) break;
  }

  closedir(dp);
  return 0;
}

static int frefs_mknod(const char *path, mode_t mode, dev_t rdev) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  int res;

  // On Linux this could just be 'mknod(path, mode, rdev)' but this is more portable
  if (S_ISREG(mode)) {
    res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
    if (res >= 0) { res = close(res); }
  } else if (S_ISFIFO(mode)) {
    res = mkfifo(path, mode);
  } else {
    res = mknod(path, mode, rdev);
  }

  return_checked_zero(res);
}

static int frefs_mkdir(const char *path, mode_t mode) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(mkdir(path, mode));
}

static int frefs_unlink(const char *path) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(unlink(path));
}

static int frefs_rmdir(const char *path) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(rmdir(path));
}

static int frefs_symlink(const char *from, const char *to) {
  INFO("%s %s %s", __func__, from, to);

  ensure_read_perm(from);
  ensure_write_perm(to);

  return_checked_zero(symlink(from, to));
}

static int frefs_rename(const char *from, const char *to) {
  INFO("%s %s %s", __func__, from, to);

  ensure_write_perm(from);
  ensure_write_perm(to);

  return_checked_zero(rename(from, to));
}

static int frefs_link(const char *from, const char *to) {
  INFO("%s %s %s", __func__, from, to);

  ensure_read_perm(from);
  ensure_write_perm(to);

  return_checked_zero(link(from, to));
}

static int frefs_chmod(const char *path, mode_t mode) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(chmod(path, mode));
}

static int frefs_chown(const char *path, uid_t uid, gid_t gid) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(lchown(path, uid, gid));
}

static int frefs_truncate(const char *path, off_t size) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(truncate(path, size));
}

static int frefs_utimens(const char *path, const struct timespec ts[2]) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW));
}

static int frefs_open(const char *path, struct fuse_file_info *finfo) {
  INFO("%s %s", __func__, path);

  if (finfo->flags & (O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_TRUNC)) {
    ensure_write_perm(path);
  }
  if (finfo->flags & (O_RDONLY | O_RDWR)) {
    ensure_read_perm(path);
  }

  int fd = open(path, finfo->flags);

  // About the return value of `close`:
  // According to https://lkml.org/lkml/2002/7/17/165, the kernel, at least Linux,
  // _will_ close the file descriptor no matter the return value is.
  // We wrote nothing therefore just ignore the value.
  if (fd != -1) close(fd);
  return_checked_zero(fd);
}

static int frefs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *finfo) {
  (void)finfo;

  INFO("%s %s", __func__, path);

  // This check is skipped for performance. `open` will do the actual check.
  // ensure_read_perm(path);

  int fd = open(path, O_RDONLY);
  if (fd == -1) { return -errno; }

  int res = pread(fd, buf, size, offset);
  close(fd);
  return_checked(res);
}

static int frefs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *finfo) {
  (void)finfo;

  INFO("%s %s", __func__, path);

  // For the same reason as frefs_read, skip the check.
  // ensure_write_perm(path);

	int fd = open(path, O_WRONLY);
	if (fd == -1) { return -errno; }

	int res = pwrite(fd, buf, size, offset);
  // FIXME: potential unawared data loss
  close(fd);
	return_checked(res);
}

static int frefs_statfs(const char *path, struct statvfs *st_buf) {
  INFO("statfs %s", path);

  ensure_read_perm(path);

  return_checked_zero(statvfs(path, st_buf));
}

static int frefs_release(const char *path, struct fuse_file_info *finfo) {
  (void) path;
  (void) finfo;

  INFO("%s %s", __func__, path);
  return 0;
}

static int frefs_fsync(const char *path, int crap, struct fuse_file_info *finfo) {
  (void) path;
  (void) crap;
  (void) finfo;

  INFO("%s %s", __func__,  path);
  return 0;
}

static int frefs_access(const char *path, int mode) {
  INFO("%s %s", __func__, path);

  int res = access(path, mode);
  if (res == -1) return -errno;

  // check again using our filters
  if (!frefs_config_get_file_permission(&config, path, FREFS_PERM_READ) ||
      ((mode & W_OK) && !frefs_config_get_file_permission(&config, path, FREFS_PERM_WRITE))) {
    return -EPERM;
  }

  return res;
}

static int frefs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(lsetxattr(path, name, value, size, flags));
}

static int frefs_getxattr(const char *path, const char *name, char *value, size_t size) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  return_checked(lgetxattr(path, name, value, size));
}

static int frefs_listxattr(const char *path, char *list, size_t size) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  return_checked(llistxattr(path, list, size));
}

static int frefs_removexattr(const char *path, const char *name) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  return_checked_zero(lremovexattr(path, name));
}

struct fuse_operations frefs_oper = {
  .getattr     = frefs_getattr,
  .readlink    = frefs_readlink,
  .readdir     = frefs_readdir,
  .mknod       = frefs_mknod,
  .mkdir       = frefs_mkdir,
  .symlink     = frefs_symlink,
  .unlink      = frefs_unlink,
  .rmdir       = frefs_rmdir,
  .rename      = frefs_rename,
  .link        = frefs_link,
  .chmod       = frefs_chmod,
  .chown       = frefs_chown,
  .truncate    = frefs_truncate,
  .utimens     = frefs_utimens,
  .open        = frefs_open,
  .read        = frefs_read,
  .write       = frefs_write,
  .statfs      = frefs_statfs,
  .release     = frefs_release,
  .fsync       = frefs_fsync,
  .access      = frefs_access,
  .setxattr    = frefs_setxattr,
  .getxattr    = frefs_getxattr,
  .listxattr   = frefs_listxattr,
  .removexattr = frefs_removexattr
};


static void print_usage(const char *progname) {
  fprintf(stderr,
    "usage: %s mountpoint options\n"
    "\n"
    "  Mounts / with regular expression filters at mountpoint\n"
    "\n"
    "options:\n"
    "  -r  --readable-config  readable config file path.\n"
    "  -w  --writable-config  writable config file path.\n"
    "  -o  opt,[opt...]       fuse mount options can be used.\n"
    "  -h  --help             print help\n"
    "  -V  --version          print version\n"
    "\n"
    "config file format:\n"
    "  A config file consists of many lines, and:\n"
    "\n"
    "    - lines which are blank or start with '#' are ignored.\n"
    "    - other lines are either:\n"
    "      - regular expression (whitelist)\n"
    "      - '!' + regular expression (blacklist)\n"
    "\n"
    "  Only POSIX extended regular expressions are supported.\n"
    "  Regular expressions will be matched against absolute paths.\n"
    "  (ex. \"/dev(/(full|null|zero))?\")\n"
    "\n"
    "  Note that filterefs checks everything using full path and\n"
    "  does not care about directory permissions. You can delete\n"
    "  /a/b if \"/a/b\" is in writable whitelist and not in blacklist,\n"
    "  directory \"/a/\" is not checked.\n\n", progname);
}

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_READABLE_CONFIG,
  KEY_WRITABLE_CONFIG,
};

static struct fuse_opt frefs_opts[] = {
  FUSE_OPT_KEY("-h",                   KEY_HELP),
  FUSE_OPT_KEY("--help",               KEY_HELP),
  FUSE_OPT_KEY("-V",                   KEY_VERSION),
  FUSE_OPT_KEY("--version",            KEY_VERSION),
  FUSE_OPT_KEY("-r %s",                KEY_READABLE_CONFIG),
  FUSE_OPT_KEY("--readable-config %s", KEY_READABLE_CONFIG),
  FUSE_OPT_KEY("-w %s",                KEY_WRITABLE_CONFIG),
  FUSE_OPT_KEY("--writable-config %s", KEY_WRITABLE_CONFIG),
  FUSE_OPT_END
};

static int frefs_parse_opt(void *data, const char *arg, int key, struct fuse_args *outargs) {
  (void) data;

  switch (key) {
    case FUSE_OPT_KEY_OPT:
      return 1;
    case KEY_HELP:
      print_usage(outargs->argv[0]);
      exit(0);
    case KEY_VERSION:
      fprintf(stdout, "filterefs %s\n", FREFS_VERSION);
      exit(0);
    case KEY_READABLE_CONFIG:
      readable_config_path = strdup(arg + (arg[1] == '-' ? 17 : 2));
      return 0;
    case KEY_WRITABLE_CONFIG:
      writable_config_path = strdup(arg + (arg[1] == '-' ? 17 : 2));
      return 0;
    case FUSE_OPT_KEY_NONOPT:
      if (!dest) {
        dest = strdup(arg);
        break;
      }
      // intentional no break
    default:
      fprintf(stderr,
        "unknown argument: %s\n"
        "see `%s -h' for usage\n",
        arg, outargs->argv[0]);
      exit(1);
  }

  return 1;
}


int main(int argc, char *argv[]) {
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  int res = fuse_opt_parse(&args, NULL, frefs_opts, frefs_parse_opt);

  if (res != 0) {
    fprintf(stderr, "invalid arguments\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  if (!readable_config_path) {
    fprintf(stderr, "warning: --readable-config is missing\n");
    fflush(stderr);
  }

  if (frefs_config_import(&config, readable_config_path, writable_config_path)) {
    fprintf(stderr, "can not load config files\n");
    exit(2);
  };

  fuse_main(args.argc, args.argv, &frefs_oper, NULL);

  return 0;
}

__attribute__((destructor)) static void cleanup() {
  if (readable_config_path) free(readable_config_path);
  if (writable_config_path) free(writable_config_path);
  if (dest) free(dest);
  frefs_config_free(&config);
}
