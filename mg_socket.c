#define REPLACE_SKIP
#include "mg_core.h"
#undef REPLACE_SKIP

REPLACE_STATIC void sockaddr_to_string(char *buf, size_t len,
                                     const union usa *usa) {
  buf[0] = '\0';
#if defined(USE_IPV6)
  inet_ntop(usa->sa.sa_family, usa->sa.sa_family == AF_INET ?
            (void *) &usa->sin.sin_addr :
            (void *) &usa->sin6.sin6_addr, buf, len);
#elif defined(_WIN32)
  // Only Windoze Vista (and newer) have inet_ntop()
  strncpy(buf, inet_ntoa(usa->sin.sin_addr), len);
#else
  inet_ntop(usa->sa.sa_family, (void *) &usa->sin.sin_addr, buf, len);
#endif
}

REPLACE_STATIC void close_all_listening_sockets(struct mg_context *ctx) {
  struct socket *sp, *tmp;
  for (sp = ctx->listening_sockets; sp != NULL; sp = tmp) {
    tmp = sp->next;
    (void) closesocket(sp->sock);
    free(sp);
  }
}

// Valid listening port specification is: [ip_address:]port[s]
// Examples: 80, 443s, 127.0.0.1:3128, 1.2.3.4:8080s
// TODO(lsm): add parsing of the IPv6 address
REPLACE_STATIC int parse_port_string(const struct vec *vec, struct socket *so) {
  int a, b, c, d, port, len;

  // MacOS needs that. If we do not zero it, subsequent bind() will fail.
  // Also, all-zeroes in the socket address means binding to all addresses
  // for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
  memset(so, 0, sizeof(*so));

  if (sscanf(vec->ptr, "%d.%d.%d.%d:%d%n", &a, &b, &c, &d, &port, &len) == 5) {
    // Bind to a specific IPv4 address
    so->lsa.sin.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
  } else if (sscanf(vec->ptr, "%d%n", &port, &len) != 1 ||
             len <= 0 ||
             len > (int) vec->len ||
             (vec->ptr[len] && vec->ptr[len] != 's' && vec->ptr[len] != ',')) {
    return 0;
  }

  so->is_ssl = vec->ptr[len] == 's';
#if defined(USE_IPV6)
  so->lsa.sin6.sin6_family = AF_INET6;
  so->lsa.sin6.sin6_port = htons((uint16_t) port);
#else
  so->lsa.sin.sin_family = AF_INET;
  so->lsa.sin.sin_port = htons((uint16_t) port);
#endif

  return 1;
}

REPLACE_STATIC int set_ports_option(struct mg_context *ctx) {
  const char *list = ctx->config[LISTENING_PORTS];
  int on = 1, success = 1;
  SOCKET sock;
  struct vec vec;
  struct socket so, *listener;

  while (success && (list = next_option(list, &vec, NULL)) != NULL) {
    if (!parse_port_string(&vec, &so)) {
      cry(fc(ctx), "%s: %.*s: invalid port spec. Expecting list of: %s",
          __func__, (int) vec.len, vec.ptr, "[IP_ADDRESS:]PORT[s|p]");
      success = 0;
    } else if (so.is_ssl &&
               (ctx->ssl_ctx == NULL || ctx->config[SSL_CERTIFICATE] == NULL)) {
      cry(fc(ctx), "Cannot add SSL socket, is -ssl_certificate option set?");
      success = 0;
    } else if ((sock = socket(so.lsa.sa.sa_family, SOCK_STREAM, 6)) ==
               INVALID_SOCKET ||
               // On Windows, SO_REUSEADDR is recommended only for
               // broadcast UDP sockets
               setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &on,
                          sizeof(on)) != 0 ||
               // Set TCP keep-alive. This is needed because if HTTP-level
               // keep-alive is enabled, and client resets the connection,
               // server won't get TCP FIN or RST and will keep the connection
               // open forever. With TCP keep-alive, next keep-alive
               // handshake will figure out that the client is down and
               // will close the server end.
               // Thanks to Igor Klopov who suggested the patch.
               setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *) &on,
                          sizeof(on)) != 0 ||
               bind(sock, &so.lsa.sa, sizeof(so.lsa)) != 0 ||
               listen(sock, SOMAXCONN) != 0) {
      closesocket(sock);
      cry(fc(ctx), "%s: cannot bind to %.*s: %s", __func__,
          (int) vec.len, vec.ptr, strerror(ERRNO));
      success = 0;
    } else if ((listener = (struct socket *)
                calloc(1, sizeof(*listener))) == NULL) {
      // NOTE(lsm): order is important: call cry before closesocket(),
      // cause closesocket() alters the errno.
      cry(fc(ctx), "%s: %s", __func__, strerror(ERRNO));
      closesocket(sock);
      success = 0;
    } else {
      *listener = so;
      listener->sock = sock;
      set_close_on_exec(listener->sock);
      listener->next = ctx->listening_sockets;
      ctx->listening_sockets = listener;
    }
  }

  if (!success) {
    close_all_listening_sockets(ctx);
  }

  return success;
}


