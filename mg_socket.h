// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
union usa {
  struct sockaddr sa;
  struct sockaddr_in sin;
#if defined(USE_IPV6)
  struct sockaddr_in6 sin6;
#endif
};

// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
  struct socket *next;  // Linkage
  SOCKET sock;          // Listening socket
  union usa lsa;        // Local socket address
  union usa rsa;        // Remote socket address
  int is_ssl;           // Is socket SSL-ed
};

REPLACE_STATIC int parse_port_string(const struct vec *vec, struct socket *so);
REPLACE_STATIC void close_all_listening_sockets(struct mg_context *ctx);
REPLACE_STATIC int set_ports_option(struct mg_context *ctx);

