#pragma once

#include <unistd.h>

pid_t translate_pid(pid_t orig_pid, const char *orig_proc, const char *new_proc);
int forward_read(const char *path, char *buf, size_t size, off_t offset, const char *socket_path);
