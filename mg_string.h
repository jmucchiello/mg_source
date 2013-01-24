#define REPLACE_SKIP
// This file and the mg_string.c should only contain utility functions
// that don't include mg_connection or mg_context pointers.
#undef REPLACE_SKIP

// Describes a string (chunk of memory).
struct vec {
  const char *ptr;
  size_t len;
};

REPLACE_STATIC char *skip_quoted(char **buf, const char *delimiters,
                         const char *whitespace, char quotechar);
REPLACE_STATIC char *skip(char **buf, const char *delimiters);
REPLACE_STATIC const char *next_option(const char *list, struct vec *val,
                               struct vec *eq_val);
REPLACE_STATIC int match_prefix(const char *pattern, int pattern_len, const char *str);
REPLACE_STATIC int url_decode(const char *src, int src_len, char *dst,
                      int dst_len, int is_form_url_encoded);
REPLACE_STATIC int get_request_len(const char *buf, int buflen);
REPLACE_STATIC void remove_double_dots_and_double_slashes(char *s);
REPLACE_STATIC void bin2str(char *to, const unsigned char *p, size_t len);
REPLACE_STATIC void url_encode(const char *src, char *dst, size_t dst_len);
REPLACE_STATIC void base64_encode(const unsigned char *src, int src_len, char *dst);

REPLACE_STATIC void mg_strlcpy(register char *dst, register const char *src, size_t n);
REPLACE_STATIC int lowercase(const char *s);
REPLACE_STATIC int mg_strncasecmp(const char *s1, const char *s2, size_t len);
REPLACE_STATIC int mg_strcasecmp(const char *s1, const char *s2);

REPLACE_STATIC char * mg_strndup(const char *ptr, size_t len);
REPLACE_STATIC char * mg_strdup(const char *str);

REPLACE_STATIC time_t parse_date_string(const char *datetime);

