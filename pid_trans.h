#pragma once

#include <unistd.h>

pid_t translate_pid(pid_t orig_pid, const char *orig_proc, const char *new_proc);
