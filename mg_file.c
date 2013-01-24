#define REPLACE_SKIP
//Functions implemented here are declared in mg_os.h
#include "mg_core.h"
#undef REPLACE_SKIP

REPLACE_STATIC int is_file_in_memory(struct mg_connection *conn, const char *path,
                             struct file *filep) {
  conn->request_info.ev_data = (void *) path;
  if ((filep->membuf = call_user(conn, MG_OPEN_FILE)) != NULL) {
    filep->size = (long) conn->request_info.ev_data;
  }
  return filep->membuf != NULL;
}

REPLACE_STATIC int is_file_opened(const struct file *filep) {
  return filep->membuf != NULL || filep->fp != NULL;
}

REPLACE_STATIC int mg_fopen(struct mg_connection *conn, const char *path,
                    const char *mode, struct file *filep) {
  if (!is_file_in_memory(conn, path, filep)) {
#ifdef _WIN32
    wchar_t wbuf[PATH_MAX], wmode[20];
    to_unicode(path, wbuf, ARRAY_SIZE(wbuf));
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, ARRAY_SIZE(wmode));
    filep->fp = _wfopen(wbuf, wmode);
#else
    filep->fp = fopen(path, mode);
#endif
  }

  return is_file_opened(filep);
}

REPLACE_STATIC void mg_fclose(struct file *filep) {
  if (filep != NULL && filep->fp != NULL) {
    fclose(filep->fp);
  }
}

REPLACE_STATIC void fclose_on_exec(struct file *filep) {
  if (filep != NULL && filep->fp != NULL) {
#ifndef _WIN32
    fcntl(fileno(filep->fp), F_SETFD, FD_CLOEXEC);
#endif
  }
}



