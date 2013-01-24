
// Like snprintf(), but never returns negative value, or a value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
REPLACE_STATIC int mg_vsnprintf(struct mg_connection *conn, char *buf, size_t buflen,
                        const char *fmt, va_list ap);
REPLACE_STATIC int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                       PRINTF_FORMAT_STRING(const char *fmt), ...)
  PRINTF_ARGS(4, 5);

REPLACE_STATIC char *mg_fgets(char *buf, size_t size, struct file *filep, char **p);
