#define REPLACE_SKIP
#include "mg_core.h"
#undef REPLACE_SKIP

// Like snprintf(), but never returns negative value, or a value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
REPLACE_STATIC int mg_vsnprintf(struct mg_connection *conn, char *buf, size_t buflen,
                        const char *fmt, va_list ap) {
  int n;

  if (buflen == 0)
    return 0;

  n = vsnprintf(buf, buflen, fmt, ap);

  if (n < 0) {
    cry(conn, "vsnprintf error");
    n = 0;
  } else if (n >= (int) buflen) {
    cry(conn, "truncating vsnprintf buffer: [%.*s]",
        n > 200 ? 200 : n, buf);
    n = (int) buflen - 1;
  }
  buf[n] = '\0';

  return n;
}

REPLACE_STATIC int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                       const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vsnprintf(conn, buf, buflen, fmt, ap);
  va_end(ap);

  return n;
}

REPLACE_STATIC char *mg_fgets(char *buf, size_t size, struct file *filep, char **p) {
  char *eof;
  size_t len;

  if (filep->membuf != NULL && *p != NULL) {
    eof = memchr(*p, '\n', &filep->membuf[filep->size] - *p);
    len = (size_t) (eof - *p) > size - 1 ? size - 1 : (size_t) (eof - *p);
    memcpy(buf, *p, len);
    buf[len] = '\0';
    *p = eof;
    return eof;
  } else if (filep->fp != NULL) {
    return fgets(buf, size, filep->fp);
  } else {
    return NULL;
  }
}



