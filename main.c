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
#define FREFS_VERSION (sizeof(FREFS_GIT_VERSION) > 1 ? FREFS_GIT_VERSION : "v0.4")

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <unistd.h>
#include <fuse.h>
#include <limits.h>
#include <linux/limits.h>

#include "config.h"
#include "utils/debug.h"


// configuration
static char *readable_config_path = NULL;
static char *writable_config_path = NULL;
static char *forward_cg_proc_path = NULL;
static int forward_cg_proc_path_len = 0;
static char *dest = NULL;

static frefs_config_t config;


#define ensure_read_perm(path) \
  if (!frefs_config_get_file_permission(&config, path, FREFS_PERM_READ)) { return -ENOENT; }
#define ensure_write_perm(path) \
{ int perm = frefs_config_get_file_permission(&config, path, FREFS_PERM_READ | FREFS_PERM_WRITE); \
  if (perm == FREFS_PERM_READ) return -EPERM; \
  else if (perm == 0) return -ENOENT; }
#define checked(exp) \
  ((exp) == -1 ? -errno : (exp))
#define checked_zero(exp) \
  ((exp) == -1 ? -errno : 0)

static const size_t PROC_FILE_MAX_SIZE = 4096;

char *fs_read(const char *path, size_t size) {
  char *result = NULL;
  FILE *fp = NULL;

  fp = fopen(path, "r");
  if (!fp) goto cleanup;

  // note: fseek won't work on special files in /proc/
  // cannot use fseek, ftell to get file size
  result = malloc(size);
  result[0] = 0;
  rewind(fp);
  fread(result, 1, size, fp);

cleanup:
  if (fp) fclose(fp);
  return result;
}

static char *path_join(const char *dirname, const char *basename) {
  if (!dirname || dirname[0] == 0) return strdup(basename);

  int dir_len = strlen(dirname);
  int base_len = strlen(basename);
  char *result = malloc(dir_len + base_len + 2);

  if (!result) return NULL;  // oom
  strcpy(result, dirname);

  // check '/'
  int offset = 1;
  if (dir_len > 0 && dirname[dir_len - 1] == '/') --offset;
  if (base_len > 0 && basename[0] == '/') --offset;
  if (offset > 0) result[dir_len] = '/';
  strcpy(result + dir_len + offset, basename);

  return result;
}

// http://womble.decadent.org.uk/readdir_r-advisory.html
static size_t dirent_buf_size(DIR * dirp) {
  static const size_t min_name_max = 512;
  long name_max = fpathconf(dirfd(dirp), _PC_NAME_MAX);
  if (name_max == -1) name_max = NAME_MAX;  // guess
  if (name_max < min_name_max) name_max = min_name_max;
  size_t name_end = (size_t)offsetof(struct dirent, d_name) + name_max + 1;
  return (name_end > sizeof(struct dirent) ? name_end : sizeof(struct dirent));
}

pid_t translate_pid(pid_t orig_pid, const char *orig_proc, const char *new_proc) {
  // TODO: find a better and more reliable way to do this
  // checking the `maps` file. this won't work well for forked processes
  pid_t result = 0;
  char *path = NULL, *content = NULL, *buf = NULL;
  FILE *fp = NULL;
  DIR *dp = NULL;
  struct dirent *de = NULL, *rde = NULL;
  size_t size, content_len, new_proc_len;

  size = strlen(orig_proc) + sizeof(orig_pid) * 3 + sizeof("//maps") + 2;
  path = malloc(size);
  if (!path) goto cleanup;
  snprintf(path, size, "%s/%ld/maps", orig_proc, (long) orig_pid);
  content = fs_read(path, PROC_FILE_MAX_SIZE);
  if (!content) goto cleanup;
  content_len = sizeof(content);

  // enum pids in new_proc
  dp = opendir(new_proc);
  if (dp == NULL) goto cleanup;
  new_proc_len = strlen(new_proc);

  de = (struct dirent *)malloc(dirent_buf_size(dp));
  if (!de) goto cleanup;

  while (readdir_r(dp, de, &rde) == 0 && rde != NULL) {
    long new_pid = 0;
    if (sscanf(rde->d_name, "%ld", &new_pid) == 0) continue;

    if (path) { free(path); path = NULL; }
    size = new_proc_len + sizeof("//maps") + sizeof(new_pid) * 3 + 2;
    path = malloc(size);
    snprintf(path, size, "%s/%ld/maps", new_proc, (long) new_pid);

    if (buf) { free(buf); buf = NULL; }
    buf = fs_read(path, PROC_FILE_MAX_SIZE);
    if (buf == NULL) continue;

    if (strncmp(buf, content, content_len) == 0) {
      result = new_pid;
      goto cleanup;
    }
  }

cleanup:
  if (path) free(path);
  if (content) free(content);
  if (buf) free(buf);
  if (de) free(de);
  if (dp) closedir(dp);
  if (fp) fclose(fp);
  return result;
}

static char *get_cgroup_name() {
  char *result = NULL;

  // lookup /proc/pid/cgroup
  pid_t pid = fuse_get_context()->pid;
  char path[sizeof(long) * 3 + sizeof("/proc//cgroup")];
  snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long)pid);
  FILE *fp = fopen(path, "r");
  if (!fp) return NULL;

  char *line = NULL;
  size_t len = 0;
  while (getline(&line, &len, fp) != -1) {
    // the line should look like:
    // 4:memory:/cgname
    char *p = strchr(line, ':');
    if (p == NULL) continue;
    if (strncmp(p, ":memory:/", sizeof(":memory:/") - 1) != 0) continue;
    if (p[sizeof(":memory:/") - 1] != '\n' && p[sizeof(":memory:/") - 1] != '\0') {
      // we got the non-empty memory cgname
      result = strdup(p + sizeof(":memory:/") - 1);
      // chomp
      int len = strlen(result);
      if (len && result[len - 1] == '\n') result[len - 1] = 0;
    }
    break;
  }
  if (line) free(line);
  fclose(fp);
  return result;
}

static const char *translate_path(const char *path) {
  if (!forward_cg_proc_path || strncmp(path, "/proc", 5) != 0)
    return path;
  char *cgname = get_cgroup_name();
  if (cgname == NULL) return path;

  int rpath_size = strlen(cgname) + forward_cg_proc_path_len + strlen(path) + 2;
  char *rpath = malloc(rpath_size);
  snprintf(rpath, rpath_size, "%s/%s%s", forward_cg_proc_path, cgname, path);
  free(cgname);

  return rpath;
}

static inline int free_rpath(const char **prpath, const char *path) {
  if (*prpath && *prpath != path) free((char *)*prpath);
  *prpath = NULL;
  return 0;
}

#define with_rpath \
  int res = 0; const char *rpath; for (rpath = translate_path(path); rpath; free_rpath(&rpath, path))
#define with_rfrom_rto \
  int res = 0; const char *rfrom, *rto; for (rfrom = translate_path(from), rto = translate_path(to); rfrom; free_rpath(&rfrom, from), free_rpath(&rto, to))

static int frefs_getattr(const char *path, struct stat *st_data) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  with_rpath {
    res = lstat(rpath, st_data);
  }

  // fake file size for /proc files. this will prevent FUSE from returning empty files
  if (strncmp(path, "/proc/", sizeof("/proc/") - 1) == 0 && S_ISREG(st_data->st_mode)) {
    // assuming /proc files are not larger than this number
    st_data->st_size = PROC_FILE_MAX_SIZE;
  }

  return checked_zero(res);
}

static int frefs_readlink(const char *path, char *buf, size_t size) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  // a special case, we need to translate pid
  if (strcmp(path, "/proc/self") == 0) do {
    static char *proc = "/proc";
    const char *rproc = translate_path(proc);
    pid_t rpid;
    if (rproc && rproc != proc) {
      // translate it between pid namespaces
      rpid = translate_pid(fuse_get_context()->pid, "/proc", rproc);
    } else {
      // we are in the same pid ns
      rpid = fuse_get_context()->pid;
    }
    free_rpath(&rproc, proc);
    if (!rpid) break;

    char rbuf[sizeof(pid_t) * 3 + 1];
    snprintf(rbuf, sizeof rbuf, "%ld", (long) rpid);
    if (size > sizeof(rbuf)) size = sizeof(rbuf);
    memcpy(buf, rbuf, size);
    return 0;
  } while (0);

  with_rpath {
    res = readlink(rpath, buf, size - 1);
    if (res != -1 && res < size) buf[res] = '\0';
  }
  return checked_zero(res);
}

static int frefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,off_t offset, struct fuse_file_info *fi) {
  DIR *dp;
  struct dirent *de = NULL, *rde = NULL;

  (void) offset;
  (void) fi;

  INFO("%s %s", __func__, path);
  ensure_read_perm(path);

  with_rpath {

    dp = opendir(rpath);
    if (dp == NULL) { res = -errno; continue; }

    de = (struct dirent *)malloc(dirent_buf_size(dp));
    if (!de) { continue; };

    while (readdir_r(dp, de, &rde) == 0 && rde != NULL) {
      int len = strlen(rde->d_name);
      if (len <= 2 && (rde->d_name[0] == '.' && (len == 1 || rde->d_name[1] == '.'))) {
        // it's '.' and '..', pass
      } else {
        // hide filtered entities
        char *joined = path_join(rpath, rde->d_name);
        int accessible = 0;
        if (joined) {  // not oom
          accessible = frefs_config_get_file_permission(&config, joined, FREFS_PERM_READ);
          free(joined);
        }
        if (!accessible) continue;
      }

      struct stat st;
      memset(&st, 0, sizeof(st));
      st.st_ino = rde->d_ino;
      st.st_mode = rde->d_type << 12;
      if (filler(buf, rde->d_name, &st, 0)) break;
    }

    free(de);
    closedir(dp);
  }

  return res;
}

static int frefs_mknod(const char *path, mode_t mode, dev_t rdev) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  with_rpath {
    // On Linux this could just be 'mknod(path, mode, rdev)' but this is more portable
    if (S_ISREG(mode)) {
      res = open(rpath, O_CREAT | O_EXCL | O_WRONLY, mode);
      if (res >= 0) { res = close(res); }
    } else if (S_ISFIFO(mode)) {
      res = mkfifo(rpath, mode);
    } else {
      res = mknod(rpath, mode, rdev);
    }
  }

  return checked_zero(res);
}

static int frefs_mkdir(const char *path, mode_t mode) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);
  with_rpath {
    res = mkdir(rpath, mode);
  }
  return checked_zero(res);
}

static int frefs_unlink(const char *path) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  with_rpath {
    res = unlink(rpath);
  }
  return checked_zero(res);
}

static int frefs_rmdir(const char *path) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);
  with_rpath {
    res = rmdir(rpath);
  }

  return checked_zero(res);
}

static int frefs_symlink(const char *from, const char *to) {
  INFO("%s %s %s", __func__, from, to);

  ensure_read_perm(from);
  ensure_write_perm(to);

  with_rfrom_rto {
    res = symlink(rfrom, rto);
  }

  return checked_zero(res);
}

static int frefs_rename(const char *from, const char *to) {
  INFO("%s %s %s", __func__, from, to);

  ensure_write_perm(from);
  ensure_write_perm(to);

  with_rfrom_rto {
    res = rename(rfrom, rto);
  }

  return checked_zero(res);
}

static int frefs_link(const char *from, const char *to) {
  INFO("%s %s %s", __func__, from, to);

  ensure_read_perm(from);
  ensure_write_perm(to);

  with_rfrom_rto {
    res = link(rfrom, rto);
  }

  return checked_zero(res);
}

static int frefs_chmod(const char *path, mode_t mode) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  with_rpath {
    res = chmod(rpath, mode);
  }

  return checked_zero(res);
}

static int frefs_chown(const char *path, uid_t uid, gid_t gid) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  with_rpath {
    res = lchown(rpath, uid, gid);
  }

  return checked_zero(res);
}

static int frefs_truncate(const char *path, off_t size) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  with_rpath {
    res = truncate(rpath, size);
  }

  return checked_zero(res);
}

static int frefs_utimens(const char *path, const struct timespec ts[2]) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  with_rpath {
    res = utimensat(0, rpath, ts, AT_SYMLINK_NOFOLLOW);
  }

  return checked_zero(res);
}

static int frefs_open(const char *path, struct fuse_file_info *finfo) {
  INFO("%s %s", __func__, path);

  if (finfo->flags & (O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_TRUNC)) {
    ensure_write_perm(path);
  }
  if (finfo->flags & (O_RDONLY | O_RDWR)) {
    ensure_read_perm(path);
  }

  with_rpath {
    res = open(rpath, finfo->flags);

    // About the return value of `close`:
    // According to https://lkml.org/lkml/2002/7/17/165, the kernel, at least Linux,
    // _will_ close the file descriptor no matter the return value is.
    // We wrote nothing therefore just ignore the value.
    if (res != -1) close(res);
  }
  return checked_zero(res);
}

static int frefs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *finfo) {
  (void)finfo;

  INFO("%s %s", __func__, path);

  // This check is skipped for performance. `open` will do the actual check.
  // ensure_read_perm(path);

  with_rpath {
    int fd = open(rpath, O_RDONLY);
    if (fd == -1) { res = -errno; continue; }

    res = pread(fd, buf, size, offset);
    close(fd);
  }
  return checked(res);
}

static int frefs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *finfo) {
  (void)finfo;

  INFO("%s %s", __func__, path);

  // For the same reason as frefs_read, skip the check.
  // ensure_write_perm(path);

  with_rpath{
    int fd = open(rpath, O_WRONLY);
    if (fd == -1) { res = -errno; continue; }

    res = pwrite(fd, buf, size, offset);
    // FIXME: potential unawared data loss
    close(fd);
  }
  return checked(res);
}

static int frefs_statfs(const char *path, struct statvfs *st_buf) {
  INFO("statfs %s", path);

  ensure_read_perm(path);

  with_rpath {
    res = statvfs(rpath, st_buf);
  }

  return checked_zero(res);
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

  with_rpath {
    res = access(rpath, mode);
  }

  if (res == 0) {
    // check again using our filters
    if (!frefs_config_get_file_permission(&config, path, FREFS_PERM_READ) ||
        ((mode & W_OK) && !frefs_config_get_file_permission(&config, path, FREFS_PERM_WRITE))) {
      return -EPERM;
    }
  }

  return checked_zero(res);
}

static int frefs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);

  with_rpath {
    res = lsetxattr(rpath, name, value, size, flags);
  }

  return checked_zero(res);
}

static int frefs_getxattr(const char *path, const char *name, char *value, size_t size) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  with_rpath {
    res = lgetxattr(rpath, name, value, size);
  }

  return checked(res);
}

static int frefs_listxattr(const char *path, char *list, size_t size) {
  INFO("%s %s", __func__, path);

  ensure_read_perm(path);

  with_rpath {
    res = llistxattr(rpath, list, size);
  }

  return checked(res);
}

static int frefs_removexattr(const char *path, const char *name) {
  INFO("%s %s", __func__, path);

  ensure_write_perm(path);
  with_rpath {
    res = lremovexattr(rpath, name);
  }

  return checked_zero(res);
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
      "                         if missing, everything is readable.\n"
      "  -w  --writable-config  writable config file path.\n"
      "                         if missing, nothing is writable.\n"
      "  --forward-cg-proc      forward /proc access. see notes below.\n"
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
      "  If a config file path starts with \"re://\" and follows a\n"
      "  string R, it is considered the same as a file containing R.\n"
      "  Using this you can avoid creating real config files.\n"
      "\n"
      "  Note that filterefs checks everything using full path and\n"
      "  does not care about directory permissions. You can delete\n"
      "  /a/b if \"/a/b\" is in writable whitelist and not in blacklist,\n"
      "  directory \"/a/\" is not checked.\n"
      "\n"
      "--forward-cg-proc:\n"
      "  This is intended to work with pid namespaces.\n"
      "  With `--forward-cg-proc /A`, when a program in memory cgroup B\n"
      "  tries to access /proc/C, it will be forwarded to /A/B/proc/C.\n"
      "\n"
      "", progname);
}

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_READABLE_CONFIG,
  KEY_WRITABLE_CONFIG,
  KEY_FORWARD_CG_PROC,
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
  FUSE_OPT_KEY("--forward-cg-proc %s", KEY_FORWARD_CG_PROC),
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
      if (readable_config_path) free(readable_config_path);
      readable_config_path = strdup(arg + (arg[1] == '-' ? 17 : 2));
      return 0;
    case KEY_WRITABLE_CONFIG:
      if (writable_config_path) free(writable_config_path);
      writable_config_path = strdup(arg + (arg[1] == '-' ? 17 : 2));
      return 0;
    case KEY_FORWARD_CG_PROC:
      if (forward_cg_proc_path) free(forward_cg_proc_path);
      forward_cg_proc_path = strdup(arg + 17);
      forward_cg_proc_path_len = strlen(forward_cg_proc_path);
      if (forward_cg_proc_path[forward_cg_proc_path_len - 1] == '/') {
        forward_cg_proc_path[--forward_cg_proc_path_len] = 0;
      }
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
