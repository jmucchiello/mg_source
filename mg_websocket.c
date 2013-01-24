#define REPLACE_SKIP
#include "mg_core.h"
#include "mg_sha1.h"
#undef REPLACE_SKIP


static void send_websocket_handshake(struct mg_connection *conn) {
  static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char buf[100], sha[20], b64_sha[sizeof(sha) * 2];
  SHA1_CTX sha_ctx;

  mg_snprintf(conn, buf, sizeof(buf), "%s%s",
              mg_get_header(conn, "Sec-WebSocket-Key"), magic);
  SHA1Init(&sha_ctx);
  SHA1Update(&sha_ctx, (unsigned char *) buf, strlen(buf));
  SHA1Final((unsigned char *) sha, &sha_ctx);
  base64_encode((unsigned char *) sha, sizeof(sha), b64_sha);
  mg_printf(conn, "%s%s%s",
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ", b64_sha, "\r\n\r\n");
}

static void read_websocket(struct mg_connection *conn) {
  unsigned char *mask, *buf = (unsigned char *) conn->buf + conn->request_len;
  int n, len, mask_len, body_len, discard_len;

  for (;;) {
    if ((body_len = conn->data_len - conn->request_len) >= 2) {
      len = buf[1] & 127;
      mask_len = buf[1] & 128 ? 4 : 0;
      if (len < 126) {
        conn->content_len = 2 + mask_len + len;
        mask = buf + 2;
      } else if (len == 126 && body_len >= 4) {
        conn->content_len = 4 + mask_len + ((((int) buf[2]) << 8) + buf[3]);
        mask = buf + 4;
      } else if (body_len >= 10) {
        conn->content_len = 10 + mask_len +
          (((uint64_t) htonl(* (uint32_t *) &buf[2])) << 32) |
          htonl(* (uint32_t *) &buf[6]);
        mask = buf + 10;
      }
    }

    if (conn->content_len > 0) {
      if (call_user(conn, MG_WEBSOCKET_MESSAGE) != NULL) {
        break;  // Callback signalled to exit
      }
      discard_len = conn->content_len > body_len ?
          body_len : (int) conn->content_len;
      memmove(buf, buf + discard_len, conn->data_len - discard_len);
      conn->data_len -= discard_len;
      conn->content_len = conn->consumed_content = 0;
    } else {
      if (wait_until_socket_is_readable(conn) == 0) {
        break;
      }
      n = pull(NULL, conn, conn->buf + conn->data_len,
               conn->buf_size - conn->data_len);
      if (n <= 0) {
        break;
      }
      conn->data_len += n;
    }
  }
}

REPLACE_STATIC void handle_websocket_request(struct mg_connection *conn) {
  if (strcmp(mg_get_header(conn, "Sec-WebSocket-Version"), "13") != 0) {
    send_http_error(conn, 426, "Upgrade Required", "%s", "Upgrade Required");
  } else if (call_user(conn, MG_WEBSOCKET_CONNECT) != NULL) {
    // Callback has returned non-NULL, do not proceed with handshake
  } else {
    send_websocket_handshake(conn);
    call_user(conn, MG_WEBSOCKET_READY);
    read_websocket(conn);
    call_user(conn, MG_WEBSOCKET_CLOSE);
  }
}

REPLACE_STATIC int is_websocket_request(const struct mg_connection *conn) {
  const char *host, *upgrade, *connection, *version, *key;

  host = mg_get_header(conn, "Host");
  upgrade = mg_get_header(conn, "Upgrade");
  connection = mg_get_header(conn, "Connection");
  key = mg_get_header(conn, "Sec-WebSocket-Key");
  version = mg_get_header(conn, "Sec-WebSocket-Version");

  return host != NULL && upgrade != NULL && connection != NULL &&
    key != NULL && version != NULL &&
    strstr(upgrade, "websocket") != NULL &&
    strstr(connection, "Upgrade") != NULL;
}

