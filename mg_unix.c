#define REPLACE_SKIP
#include "mg_core.h"
#ifndef _WIN32
#undef REPLACE_SKIP

REPLACE_STATIC int mg_stat(struct mg_connection *conn, const char *path,
                   struct file *filep) {
  struct stat st;

  if (!is_file_in_memory(conn, path, filep) && !stat(path, &st)) {
    filep->size = st.st_size;
    filep->modification_time = st.st_mtime;
    filep->is_directory = S_ISDIR(st.st_mode);
  } else {
    filep->modification_time = (time_t) 0;
  }

  return filep->membuf != NULL || filep->modification_time != (time_t) 0;
}

static void set_close_on_exec(int fd) {
  fcntl(fd, F_SETFD, FD_CLOEXEC);
}

REPLACE_STATIC mg_start_thread(mg_thread_func_t func, void *param) {
  pthread_t thread_id;
  pthread_attr_t attr;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  // TODO(lsm): figure out why mongoose dies on Linux if next line is enabled
  // (void) pthread_attr_setstacksize(&attr, sizeof(struct mg_connection) * 5);

  return pthread_create(&thread_id, &attr, func, param);
}

#ifndef NO_CGI
REPLACE_STATIC pid_t spawn_process(struct mg_connection *conn, const char *prog,
                           char *envblk, char *envp[], int fd_stdin,
                           int fd_stdout, const char *dir) {
  pid_t pid;
  const char *interp;

  envblk = NULL; // Unused

  if ((pid = fork()) == -1) {
    // Parent
    send_http_error(conn, 500, http_500_error, "fork(): %s", strerror(ERRNO));
  } else if (pid == 0) {
    // Child
    if (chdir(dir) != 0) {
      cry(conn, "%s: chdir(%s): %s", __func__, dir, strerror(ERRNO));
    } else if (dup2(fd_stdin, 0) == -1) {
      cry(conn, "%s: dup2(%d, 0): %s", __func__, fd_stdin, strerror(ERRNO));
    } else if (dup2(fd_stdout, 1) == -1) {
      cry(conn, "%s: dup2(%d, 1): %s", __func__, fd_stdout, strerror(ERRNO));
    } else {
      (void) dup2(fd_stdout, 2);
      (void) close(fd_stdin);
      (void) close(fd_stdout);

      // After exec, all signal handlers are restored to their default values,
      // with one exception of SIGCHLD. According to POSIX.1-2001 and Linux's
      // implementation, SIGCHLD's handler will leave unchanged after exec
      // if it was set to be ignored. Restore it to default action.
      signal(SIGCHLD, SIG_DFL);

      interp = conn->ctx->config[CGI_INTERPRETER];
      if (interp == NULL) {
        (void) execle(prog, prog, NULL, envp);
        cry(conn, "%s: execle(%s): %s", __func__, prog, strerror(ERRNO));
      } else {
        (void) execle(interp, interp, prog, NULL, envp);
        cry(conn, "%s: execle(%s %s): %s", __func__, interp, prog,
            strerror(ERRNO));
      }
    }
    exit(EXIT_FAILURE);
  }

  // Parent. Close stdio descriptors
  (void) close(fd_stdin);
  (void) close(fd_stdout);

  return pid;
}
#endif // !NO_CGI

REPLACE_STATIC int set_non_blocking_mode(SOCKET sock) {
  int flags;

  flags = fcntl(sock, F_GETFL, 0);
  (void) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  return 0;
}

#define REPLACE_SKIP
#endif // !WIN32
#undef REPLACE_SKIP

