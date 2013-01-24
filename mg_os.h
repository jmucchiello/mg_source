
struct file {
  int is_directory;
  time_t modification_time;
  int64_t size;
  FILE *fp;
  const char *membuf;   // Non-NULL if file data is in memory
};
#define STRUCT_FILE_INITIALIZER {0, 0, 0, NULL, NULL}

//// These functions are implemented in mg_file.c
REPLACE_STATIC int is_file_in_memory(struct mg_connection *conn, const char *path,
                             struct file *filep);
REPLACE_STATIC int is_file_opened(const struct file *filep);
REPLACE_STATIC int mg_fopen(struct mg_connection *conn, const char *path,
                    const char *mode, struct file *filep);
REPLACE_STATIC void mg_fclose(struct file *filep);
REPLACE_STATIC void fclose_on_exec(struct file *filep);

//// These functions are implemented in mg_win32.c and mg_unix.c
REPLACE_STATIC int mg_stat(struct mg_connection *conn, const char *path,
                   struct file *filep);
#ifndef NO_CGI
REPLACE_STATIC pid_t spawn_process(struct mg_connection *conn, const char *prog,
                           char *envblk, char *envp[], int fd_stdin,
                           int fd_stdout, const char *dir);
#endif
REPLACE_STATIC int set_non_blocking_mode(SOCKET sock);
REPLACE_STATIC int mg_mkdir(const char *path, int mode);


