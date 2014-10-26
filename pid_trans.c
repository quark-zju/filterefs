#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

extern size_t dirent_buf_size(DIR * dirp);

char *fs_read(const char *path, size_t size) {
  char *result = NULL;
  FILE *fp = NULL;

  fp = fopen(path, "r");
  if (!fp) goto cleanup;

  // note: fseek won't work on special files in /proc/
  // cannot use fseek, ftell to get file size
  result = malloc(size + 1);
  memset(result, 0, size + 1);
  result[0] = 0;
  rewind(fp);
  fread(result, 1, size, fp);

cleanup:
  if (fp) fclose(fp);
  return result;
}

typedef int enum_pid_f(pid_t, void *);

static void enum_pids(const char *proc_path, enum_pid_f callback, void *arg) {
  DIR *dp = NULL;
  struct dirent *de = NULL, *rde = NULL;

  // enum pids in path
  dp = opendir(proc_path);
  if (dp == NULL) goto cleanup;

  de = (struct dirent *)malloc(dirent_buf_size(dp));
  if (!de) goto cleanup;

  while (readdir_r(dp, de, &rde) == 0 && rde != NULL) {
    long cur_pid = 0;
    if (sscanf(rde->d_name, "%ld", &cur_pid) == 0) continue;
    int stop = callback((pid_t)cur_pid, arg);
    if (stop) break;
  }

cleanup:
  if (de) free(de);
  if (dp) closedir(dp);
}

struct cb_qpid_arg {
  pid_t *resultp;
  pid_t orig_pid;
  int sfd;
};

static int cb_qpid(pid_t pid, void *varg) {
  struct cb_qpid_arg *arg = varg;
  int sfd = arg->sfd;
  int stop = 0;

  struct msghdr msgh;
  struct iovec iov;
  struct ucred *ucredp;
  long data;
  union {
    struct cmsghdr cmh;
    char control[CMSG_SPACE(sizeof(struct ucred))];
  } control_un;
  struct cmsghdr *cmhp;

  control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
  control_un.cmh.cmsg_level = SOL_SOCKET;
  control_un.cmh.cmsg_type = SCM_CREDENTIALS;

  msgh.msg_control = control_un.control;
  msgh.msg_controllen = sizeof(control_un.control);

  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  iov.iov_base = &data;
  iov.iov_len = sizeof(data);

  msgh.msg_name = NULL;
  msgh.msg_namelen = 0;

  data = pid;
  if (send(sfd, &data, sizeof data, MSG_NOSIGNAL) == -1) goto cleanup;

  if (recvmsg(sfd, &msgh, 0) == -1) goto cleanup;

  cmhp = CMSG_FIRSTHDR(&msgh);
  if (cmhp == NULL || cmhp->cmsg_len != CMSG_LEN(sizeof(struct ucred))) goto cleanup;
  if (cmhp->cmsg_level != SOL_SOCKET) goto cleanup;
  if (cmhp->cmsg_type != SCM_CREDENTIALS) goto cleanup;

  ucredp = (struct ucred *) CMSG_DATA(cmhp);
  if (ucredp->pid == arg->orig_pid) {
    *(arg->resultp) = pid;
    stop = 1;
  }

cleanup:
  return stop;
}

static int connect_service(const char *socket_path, char mode) {
  int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sfd == -1) goto failure;

  struct sockaddr_un sun;
  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, socket_path);

  if (connect(sfd, (struct sockaddr*)&sun, sizeof(sun)) == -1) goto failure;

  int optval = 1;
  if (setsockopt(sfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) goto failure;

  if (send(sfd, &mode, sizeof mode, MSG_NOSIGNAL) == -1) goto failure;

  return sfd;

failure:
  if (sfd != -1) close(sfd);
  return -1;
}

static pid_t query_pid(const char *proc_path, const char *socket_path, pid_t orig_pid) {
  pid_t result = 0;
  // as we only know orig_pid (pid in parent namespace),
  // and we are not root, not able to send struct ucred with
  // a fake pid. enum all pids.
  int sfd = connect_service(socket_path, 'p');
  if (sfd == -1) goto cleanup;

  struct cb_qpid_arg arg;
  arg.resultp = &result;
  arg.sfd = sfd;
  arg.orig_pid = orig_pid;
  enum_pids(proc_path, cb_qpid, &arg);

cleanup:
  if (sfd != -1) close(sfd);
  return result;
}

struct cb_fsip_arg {
  pid_t *resultp;
  const char *fname;
  const char *content;
  const char *proc_path;
  size_t path_len, content_len;
};

static int cb_fsip(pid_t pid, void *varg) {
  char *path = NULL, *buf = NULL;
  int stop = 0;
  struct cb_fsip_arg *arg = varg;

  path = malloc(arg->path_len);
  if (!path) goto cleanup;

  snprintf(path, arg->path_len, "%s/%ld/%s", arg->proc_path, (long) pid, arg->fname);
  buf = fs_read(path, arg->content_len);
  if (!buf) goto cleanup;

  if (strncmp(buf, arg->content, arg->content_len) == 0) {
    *(arg->resultp) = pid;
    stop = 1;
  }

cleanup:
  if (buf) free(buf);
  if (path) free(path);
  return stop;
}

static pid_t find_same_in_proc(const char *proc_path, const char *fname, const char *content) {
  struct cb_fsip_arg arg;
  pid_t result = 0;
  arg.resultp = &result;
  arg.proc_path = proc_path;
  arg.fname = fname;
  arg.content = content;
  arg.content_len = strlen(content);
  arg.path_len = strlen(proc_path) + strlen(fname) + sizeof(long) * 3 + 8;

  enum_pids(proc_path, cb_fsip, (void *)&arg);
  return result;
}

int forward_read(const char *path, char *buf, size_t size, off_t offset, const char *socket_path) {
  errno = EIO;
  int sfd = connect_service(socket_path, 'r');
  if (sfd == -1) goto failure;

  long len = strlen(path) + 1;
  if (send(sfd, &len, sizeof len, MSG_NOSIGNAL) == -1) goto failure;
  if (send(sfd, path, len, MSG_NOSIGNAL) == -1) goto failure;
  if (send(sfd, &size, sizeof size, MSG_NOSIGNAL) == -1) goto failure;
  if (send(sfd, &offset, sizeof offset, MSG_NOSIGNAL) == -1) goto failure;

  ssize_t n;
  if (recv(sfd, &n, sizeof n, MSG_WAITALL) != sizeof n) goto failure;
  if (n > size) n = size;
  recv(sfd, buf, n, MSG_WAITALL);
  close(sfd);
  return n;

failure:
  if (sfd != -1) close(sfd);
  return -1;
}

pid_t translate_pid(pid_t orig_pid, const char *orig_proc, const char *new_proc) {
  pid_t result = 0;
  char *path = NULL, *content = NULL;
  size_t size, i;

  // the "reliable" method, query pid using sockets
  // require a pid-translate service running
  size = strlen(new_proc) + sizeof("/../pid-translate.sock");
  path = malloc(size);
  snprintf(path, size, "%s%s", new_proc, "/../pid-translate.sock");
  if (!path) goto cleanup;
  if (access(path, F_OK) == 0) {
    result = query_pid(new_proc, path, orig_pid);
    if (result) goto cleanup;
  }

  // the stupid method
  // checking the `smaps`, `maps` file. this won't work well for forked processes
  static const char fnames[][64]  = {"smaps", "maps"};

  size = strlen(orig_proc) + sizeof(orig_pid) * 3 + sizeof(fnames[0]) + 4;
  if (path) { free(path); path = NULL; }
  path = malloc(size);
  if (!path) goto cleanup;

  for (i = 0; i < sizeof(fnames) / sizeof(fnames[0]); ++i) {
    snprintf(path, size, "%s/%ld/maps", orig_proc, (long) orig_pid);
    if (content) { free(content); content = NULL; }
    content = fs_read(path, 16384 /* max assumed proc file size */);
    if (!content) continue;
    pid_t new_pid = find_same_in_proc(new_proc, fnames[i], content);
    if (new_pid > 0) {
      result = new_pid;
      goto cleanup;
    }
  }

cleanup:
  if (path) free(path);
  if (content) free(content);
  return result;
}
