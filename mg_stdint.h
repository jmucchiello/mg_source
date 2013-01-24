#if defined(HAVE_STDINT)
#include <stdint.h>
#else
typedef unsigned int  uint32_t;
typedef unsigned short  uint16_t;
typedef unsigned __int64 uint64_t;
typedef __int64   int64_t;
#define INT64_MAX  9223372036854775807
#endif // HAVE_STDINT

#define REPLACE_SKIP
// Defined in mg_md5.c
#undef REPLACE_SKIP
REPLACE_STATIC int is_big_endian(void);

