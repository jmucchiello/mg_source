//#define REPLACE_STATIC

#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS // Disable deprecation warning in VS2005
#else
#ifdef __linux__
#define _XOPEN_SOURCE 600     // For flockfile() on Linux
#endif
#define _LARGEFILE_SOURCE     // Enable 64-bit file offsets
#define __STDC_FORMAT_MACROS  // <inttypes.h> wants this for C++
#define __STDC_LIMIT_MACROS   // C++ wants that for INT64_MAX
#endif

#if defined (_MSC_VER)
// conditional expression is constant: introduced by FD_SET(..)
#pragma warning (disable : 4127)
// non-constant aggregate initializer: issued due to missing C99 support
#pragma warning (disable : 4204)
#endif

// Disable WIN32_LEAN_AND_MEAN.
// This makes windows.h always include winsock2.h
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif

#if defined(__SYMBIAN32__)
#define NO_SSL // SSL is not supported
#define NO_CGI // CGI is not supported
#define PATH_MAX FILENAME_MAX
#endif // __SYMBIAN32__

#ifndef _WIN32_WCE // Some ANSI #includes are not available on Windows CE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#endif // !_WIN32_WCE

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>

#if defined(_WIN32) && !defined(__SYMBIAN32__) // Windows specific
#define _WIN32_WINNT 0x0400 // To make it link in VS2005
#include <windows.h>

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif

#ifndef _WIN32_WCE
#include <process.h>
#include <direct.h>
#include <io.h>
#else // _WIN32_WCE
#define NO_CGI // WinCE has no pipes

typedef long off_t;

#define errno   GetLastError()
#define strerror(x)  _ultoa(x, (char *) _alloca(sizeof(x) *3 ), 10)
#endif // _WIN32_WCE

// Visual Studio 6 does not know __func__ or __FUNCTION__
// The rest of MS compilers use __FUNCTION__, not C99 __func__
// Also use _strtoui64 on modern M$ compilers
#if defined(_MSC_VER) && _MSC_VER < 1300
#define STRX(x) #x
#define STR(x) STRX(x)
#define __func__ "line " STR(__LINE__)
#define strtoull(x, y, z) strtoul(x, y, z)
#define strtoll(x, y, z) strtol(x, y, z)
#else
#define __func__  __FUNCTION__
#define strtoull(x, y, z) _strtoui64(x, y, z)
#define strtoll(x, y, z) _strtoi64(x, y, z)
#endif // _MSC_VER

#define ERRNO   GetLastError()
#define NO_SOCKLEN_T
#define O_NONBLOCK  0
#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK  WSAEWOULDBLOCK
#endif // !EWOULDBLOCK
#define _POSIX_
#define INT64_FMT  "I64d"

#define WINCDECL __cdecl
#define SHUT_WR 1
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define mg_sleep(x) Sleep(x)

#define pipe(x) _pipe(x, MG_BUF_LEN, _O_BINARY)
#define popen(x, y) _popen(x, y)
#define pclose(x) _pclose(x)
#define close(x) _close(x)
#define dlsym(x,y) GetProcAddress((HINSTANCE) (x), (y))
#define RTLD_LAZY  0
#define fseeko(x, y, z) _lseeki64(_fileno(x), (y), (z))
#define fdopen(x, y) _fdopen((x), (y))
#define write(x, y, z) _write((x), (y), (unsigned) z)
#define read(x, y, z) _read((x), (y), (unsigned) z)
#define flockfile(x) EnterCriticalSection(&global_log_file_lock)
#define funlockfile(x) LeaveCriticalSection(&global_log_file_lock)
#define sleep(x) Sleep((x) * 1000)
#define set_close_on_exec(x) // No FD_CLOEXEC on Windows

#if !defined(fileno)
#define fileno(x) _fileno(x)
#endif // !fileno MINGW #defines fileno

typedef HANDLE pthread_mutex_t;
typedef struct {HANDLE signal, broadcast;} pthread_cond_t;
typedef DWORD pthread_t;
#define pid_t HANDLE // MINGW typedefs pid_t to int. Using #define here.

REPLACE_STATIC int pthread_mutex_lock(pthread_mutex_t *);
REPLACE_STATIC int pthread_mutex_unlock(pthread_mutex_t *);
//REPLACE_STATIC void to_unicode(const char *path, wchar_t *wbuf, size_t wbuf_len);
struct file;
REPLACE_STATIC char *mg_fgets(char *buf, size_t size, struct file *filep, char **p);

#include "mg_stdint.h"
// POSIX dirent interface
struct dirent {
  char d_name[PATH_MAX];
};

typedef struct DIR {
  HANDLE   handle;
  WIN32_FIND_DATAW info;
  struct dirent  result;
} DIR;

REPLACE_STATIC DIR * opendir(const char *name);
REPLACE_STATIC int closedir(DIR *dir);
REPLACE_STATIC struct dirent *readdir(DIR *dir);
REPLACE_STATIC HANDLE dlopen(const char *dll_name, int flags);
#define SIGKILL 0
REPLACE_STATIC int kill(pid_t pid, int sig_num);
REPLACE_STATIC int mg_remove(const char *path);
REPLACE_STATIC void to_unicode(const char *path, wchar_t *wbuf, size_t wbuf_len);

// Mark required libraries
#pragma comment(lib, "Ws2_32.lib")

#else    // UNIX  specific
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>
#include <netdb.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#if !defined(NO_SSL_DL) && !defined(NO_SSL)
#include <dlfcn.h>
#endif
#include <pthread.h>
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
#define mg_mkdir(x, y) mkdir(x, y)
#define mg_remove(x) remove(x)
#define mg_rename(x, y) rename(x, y)
#define mg_sleep(x) usleep((x) * 1000)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;
#define WINCDECL

#endif // End of Windows and UNIX specific includes

#include "mongoose.h"

#define MONGOOSE_VERSION "3.6"
#define PASSWORDS_FILE_NAME ".htpasswd"
#define CGI_ENVIRONMENT_SIZE 4096
#define MAX_CGI_ENVIR_VARS 64
#define MG_BUF_LEN 8192
#define MAX_REQUEST_SIZE 16384
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#ifdef _WIN32
static CRITICAL_SECTION global_log_file_lock;
static pthread_t pthread_self(void) {
  return GetCurrentThreadId();
}
#endif // _WIN32

#ifdef DEBUG_TRACE
#undef DEBUG_TRACE
#define DEBUG_TRACE(x)
#else
#if defined(DEBUG)
#define DEBUG_TRACE(x) do { \
  flockfile(stdout); \
  printf("*** %lu.%p.%s.%d: ", \
         (unsigned long) time(NULL), (void *) pthread_self(), \
         __func__, __LINE__); \
  printf x; \
  putchar('\n'); \
  fflush(stdout); \
  funlockfile(stdout); \
} while (0)
#else
#define DEBUG_TRACE(x)
#endif // DEBUG
#endif // DEBUG_TRACE

// Darwin prior to 7.0 and Win32 do not have socklen_t
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif // NO_SOCKLEN_T
#define _DARWIN_UNLIMITED_SELECT

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if !defined(SOMAXCONN)
#define SOMAXCONN 100
#endif

#if !defined(PATH_MAX)
#define PATH_MAX 4096
#endif

static const char *http_500_error = "Internal Server Error";

#include "mg_string.h"
#include "mg_os.h"

#ifdef USE_LUA
REPLACE_STATIC void handle_lsp_request(struct mg_connection *conn, const char *path,
                               struct file *filep);
#endif
#ifdef USE_CGI
REPLACE_STATIC void handle_cgi_request(struct mg_connection *conn, const char *prog);
#endif
#ifndef NO_USE_SSL
#include "mg_ssl.h"
#endif

#include "mg_socket.h"

// NOTE(lsm): this enum shoulds be in sync with the config_options below.
enum {
  CGI_EXTENSIONS, CGI_ENVIRONMENT, PUT_DELETE_PASSWORDS_FILE, CGI_INTERPRETER,
  PROTECT_URI, AUTHENTICATION_DOMAIN, SSI_EXTENSIONS, THROTTLE,
  ACCESS_LOG_FILE, ENABLE_DIRECTORY_LISTING, ERROR_LOG_FILE,
  GLOBAL_PASSWORDS_FILE, INDEX_FILES, ENABLE_KEEP_ALIVE, ACCESS_CONTROL_LIST,
  EXTRA_MIME_TYPES, LISTENING_PORTS, DOCUMENT_ROOT, SSL_CERTIFICATE,
  NUM_THREADS, RUN_AS_USER, REWRITE, HIDE_FILES,
  NUM_OPTIONS
};

static const char *config_options[] = {
  "C", "cgi_pattern", "**.cgi$|**.pl$|**.php$",
  "E", "cgi_environment", NULL,
  "G", "put_delete_passwords_file", NULL,
  "I", "cgi_interpreter", NULL,
  "P", "protect_uri", NULL,
  "R", "authentication_domain", "mydomain.com",
  "S", "ssi_pattern", "**.shtml$|**.shtm$",
  "T", "throttle", NULL,
  "a", "access_log_file", NULL,
  "d", "enable_directory_listing", "yes",
  "e", "error_log_file", NULL,
  "g", "global_passwords_file", NULL,
  "i", "index_files", "index.html,index.htm,index.cgi,index.shtml,index.php",
  "k", "enable_keep_alive", "no",
  "l", "access_control_list", NULL,
  "m", "extra_mime_types", NULL,
  "p", "listening_ports", "8080",
  "r", "document_root",  ".",
  "s", "ssl_certificate", NULL,
  "t", "num_threads", "20",
  "u", "run_as_user", NULL,
  "w", "url_rewrite_patterns", NULL,
  "x", "hide_files_patterns", NULL,
  NULL
};
#define ENTRIES_PER_CONFIG_OPTION 3

struct mg_context {
  volatile int stop_flag;       // Should we stop event loop
  SSL_CTX *ssl_ctx;             // SSL context
  SSL_CTX *client_ssl_ctx;      // Client SSL context
  char *config[NUM_OPTIONS];    // Mongoose configuration parameters
  mg_callback_t user_callback;  // User-defined callback function
  void *user_data;              // User-defined data

  struct socket *listening_sockets;

  volatile int num_threads;  // Number of threads
  pthread_mutex_t mutex;     // Protects (max|num)_threads
  pthread_cond_t  cond;      // Condvar for tracking workers terminations

  struct socket queue[20];   // Accepted sockets
  volatile int sq_head;      // Head of the socket queue
  volatile int sq_tail;      // Tail of the socket queue
  pthread_cond_t sq_full;    // Signaled when socket is produced
  pthread_cond_t sq_empty;   // Signaled when socket is consumed
};

struct mg_connection {
  struct mg_request_info request_info;
  struct mg_context *ctx;
  SSL *ssl;                   // SSL descriptor
  struct socket client;       // Connected client
  time_t birth_time;          // Time when request was received
  int64_t num_bytes_sent;     // Total bytes sent to client
  int64_t content_len;        // Content-Length header value
  int64_t consumed_content;   // How many bytes of content have been read
  char *buf;                  // Buffer for received data
  char *path_info;            // PATH_INFO part of the URL
  int must_close;             // 1 if connection must be closed
  int buf_size;               // Buffer size
  int request_len;            // Size of the request + headers in a buffer
  int data_len;               // Total size of data in a buffer
  int status_code;            // HTTP reply status code, e.g. 200
  int throttle;               // Throttling, bytes/sec. <= 0 means no throttle
  time_t last_throttle_time;  // Last time throttled data was sent
  int64_t last_throttle_bytes;// Bytes sent this second
};

REPLACE_STATIC void *call_user(struct mg_connection *conn, enum mg_event event);
REPLACE_STATIC const char *get_header(const struct mg_request_info *ri,
                              const char *name);
REPLACE_STATIC void cry(struct mg_connection *conn,
                PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);
REPLACE_STATIC struct mg_connection *fc(struct mg_context *ctx);

REPLACE_STATIC void send_http_error(struct mg_connection *, int, const char *,
                            PRINTF_FORMAT_STRING(const char *fmt), ...)
  PRINTF_ARGS(4, 5);
REPLACE_STATIC int forward_body_data(struct mg_connection *conn, FILE *fp,
                             SOCKET sock, SSL *ssl);
REPLACE_STATIC int read_request(FILE *fp, struct mg_connection *conn,
                        char *buf, int bufsiz, int *nread);
REPLACE_STATIC void parse_http_headers(char **buf, struct mg_request_info *ri);
REPLACE_STATIC int parse_http_request(char *buf, int len, struct mg_request_info *ri);
REPLACE_STATIC int parse_http_response(char *buf, int len, struct mg_request_info *ri);
REPLACE_STATIC void send_file_data(struct mg_connection *conn, struct file *filep,
                           int64_t offset, int64_t len);
REPLACE_STATIC void sockaddr_to_string(char *buf, size_t len,
                                     const union usa *usa);

#include "mg_libc.h"
