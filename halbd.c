#include <st.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFSIZE 8192
#define STACKSIZE (1024*1024*32) // 32 kb is enough for anyone
#define TIMEOUT 10000000 // 10 seconds

#define RSA_SERVER_CERT "server.crt"
#define RSA_SERVER_KEY "server.key"

static int stb_new(BIO *bi)
{
  bi->init = 0;
  bi->ptr = NULL;
  bi->flags = 0;
  return 1;
}

static int stb_free(BIO *a)
{
  if (a == NULL)
    return 0;
  if (a->shutdown)
  {
    if (a->init)
      st_netfd_close(a->ptr);
    a->init = 0;
    a->flags = 0;
  }
  return 1;
}

static int stb_read(BIO *b, char *out, int outl)
{
  return st_read((st_netfd_t)b->ptr, out, outl, TIMEOUT);
}

static int stb_write(BIO *b, const char *in, int inl)
{
  return st_write((st_netfd_t)b->ptr, in, inl, TIMEOUT);
}

static int stb_puts(BIO *bp, const char *str)
{
  return stb_write(bp, str, strlen(str));
}

static long stb_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  int *ip;
  switch (cmd)
  {
    case BIO_C_SET_FD:
      stb_free(b);
      b->ptr = st_netfd_open_socket(*((int *)ptr));
      b->shutdown = (int)num;
      b->init = 1;
      return 1;
    case BIO_C_GET_FD:
      if (b->init)
      {
        ip=(int *)ptr;
        if (ip != NULL)
          *ip = st_netfd_fileno((st_netfd_t)b->ptr);
        return *ip;
      }
      else
        return -1;
    case BIO_CTRL_GET_CLOSE:
      return b->shutdown;
    case BIO_CTRL_SET_CLOSE:
      b->shutdown = (int)num;
      return 1;
    case BIO_CTRL_DUP: case BIO_CTRL_FLUSH:
      return 1;
    case BIO_CTRL_RESET: case BIO_C_FILE_SEEK: case BIO_C_FILE_TELL:
    case BIO_CTRL_INFO: case BIO_CTRL_PENDING: case BIO_CTRL_WPENDING:
    default:
      return 0;
  }
}

void *handle_connection(SSL *ssl)
{
  struct sockaddr_in sa_serv;
  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  char xf4[64];
  int lenxf4 = sprintf(xf4, "X-Forwarded-For: %s\r\n", (char *)ssl->msg_callback_arg);
  int size = 1;
  free(ssl->msg_callback_arg);
  ssl->msg_callback_arg = NULL;

  if (sock < 0)
  {
    perror("socket");
    goto cleanup;
  }

  st_netfd_t server_sock = st_netfd_open_socket(sock);
  if (!server_sock)
  {
    perror("st_netfd_open_socket");
    goto cleanup;
  }

  memset(&sa_serv, 0, sizeof(sa_serv));
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr.s_addr = inet_addr("127.0.0.1");
  sa_serv.sin_port = htons(8080);

  if (st_connect(server_sock, (struct sockaddr *)&sa_serv, sizeof(sa_serv), TIMEOUT))
  {
    perror("st_connect");
    goto cleanup;
  }

  setsockopt(st_netfd_fileno(server_sock), IPPROTO_TCP, TCP_NODELAY, &size, sizeof(size));
  SSL_set_accept_state(ssl);

  st_thread_t c2s;
  st_thread_t s2c;

  void *client_to_server(void *arg)
  {
    char buffer[BUFSIZE + sizeof(xf4) + 1];
    char header[BUFSIZE], *hptr = header;
    int state = 0, scan = 0, buflen = 0, len = 0;
    int content_length = -1;

    while (ssl && (len = SSL_read(ssl, buffer + buflen, BUFSIZE - buflen)) > 0)
    {
      buflen += len;

      for (; scan < buflen; scan++)
      {
        switch(state)
        {
          case 0: // read request
            if (buffer[scan] == '\n')
            {
              memmove(&buffer[scan+lenxf4+1], &buffer[scan+1], buflen - scan);
              memcpy(&buffer[scan+1], xf4, lenxf4);
              buflen += lenxf4;
              scan += lenxf4;
              state = 1;
              content_length = -1;
            }
            continue;
          case 1: // read headers, have appended xf4
            if (buffer[scan] == '\n')
            {
              if (hptr - header < 3) // apparent end of headers
              {
                if (content_length > 0)
                  state = 2;
                else if (content_length == -2)
                  state = 3;
                else
                  state = 0;
              }
              else
              {
                *hptr = 0;
                if (toupper(header[0]) == 'C' && toupper(header[8]) == 'L'
                      && !strncasecmp(header, "Content-Length: ", 16)
                      && isdigit(header[17]))
                  content_length = atoi(&header[16]);
                if (toupper(header[0]) == 'T' && toupper(header[9]) == 'E'
                      && tolower(header[19]) == 'c'
                      && !strncasecmp(header, "Transfer-Encoding: chunked", 25))
                  content_length = -2;
              }
              hptr = header;
              *hptr = 0;
            }
            else
              *hptr++ = buffer[scan];
            continue;
          case 2: // read body with content-length
            if (scan + content_length <= buflen)
            {
              scan += content_length;
              state = 0;
            }
            else
            {
              content_length -= (buflen - scan);
              scan = buflen;
            }
            continue;
          case 3: // TODO read chunked body
            continue;
        }
      }

      if ((len = st_write(server_sock, buffer, buflen, TIMEOUT)) <= 0)
        break;
      else if (len == buflen)
      {
        scan = 0;
        buflen = 0;
      }
      else
      {
        memmove(buffer, buffer + len, buflen - len);
        buflen -= len;
        scan -= len;
      }
    }
    st_thread_interrupt(s2c);
    return NULL;
  }

  void *server_to_client(void *arg)
  {
    char buffer[BUFSIZE];
    int buflen = 0, len;
    while (ssl && (len = st_read(server_sock, buffer + buflen, sizeof(buffer) - buflen, TIMEOUT)) > 0)
    {
      buflen += len;
      if ((len = SSL_write(ssl, buffer, buflen)) <= 0)
        break;
      else if (len == buflen)
        buflen = 0;
      else
      {
        memmove(buffer, buffer + len, buflen - len);
        buflen -= len;
      }
    }
    st_thread_interrupt(c2s);
    return NULL;
  }

  c2s = st_thread_create(client_to_server, NULL, 1, STACKSIZE);
  if (!c2s)
  {
    perror("st_thread_create");
    goto cleanup;
  }
  s2c = st_thread_create(server_to_client, NULL, 1, STACKSIZE);
  st_thread_join(c2s, NULL);
  st_thread_join(s2c, NULL);

  cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    st_netfd_close(server_sock);

  return NULL;
}

int main(int argc, char **argv)
{
  short int s_port = 1025;
  int listen_sock;
  struct sockaddr_in sa_serv;
  SSL_CTX *ctx;
  SSL_METHOD *meth;
  st_netfd_t listener, client;
  BIO_METHOD methods_stbp =
  {
    BIO_TYPE_SOCKET,
    "st_sock_t",
    stb_write,
    stb_read,
    stb_puts,
    NULL, /* stb_gets, */
    stb_ctrl,
    stb_new,
    stb_free,
    NULL,
  };

  SSL_library_init();
  SSL_load_error_strings();

  if (!(meth = SSLv23_server_method()) ||
      !(ctx = SSL_CTX_new(meth)) ||
      (SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) ||
      (SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0))
  {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  if ((listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) <= 0)
  {
    perror("socket");
    return 1;
  }

  int x = 1;
  if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &x, sizeof(x)) < 0)
  {
    perror("setsockopt");
    return 1;
  }

  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port = htons(s_port);

  if (bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv)) < 0)
  {
    perror("bind");
    return 1;
  }

  if (listen(listen_sock, SOMAXCONN) < 0)
  {
    perror("bind");
    return 1;
  }

  fork();
  fork();

  st_init();
  #if defined(ST_EVENTSYS_ALT)
  st_set_eventsys(ST_EVENTSYS_ALT);
  #endif
  st_randomize_stacks(1);
  listener = st_netfd_open_socket(listen_sock);

  for (;;)
  {
    struct sockaddr_in addr;
    int adlen = sizeof(addr);
    if ((client = st_accept(listener, (struct sockaddr*)&addr, &adlen, TIMEOUT)))
    {
      int client_sock = st_netfd_fileno(client);
      int size = 1;
      st_netfd_free(client);
      setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &size, sizeof(size));
      if (client_sock >= 0)
      {
        SSL *ssl = SSL_new(ctx);
        BIO *ret = BIO_new(&methods_stbp);
        BIO_set_fd(ret, client_sock, 1);
        SSL_set_bio(ssl, ret, ret);
        ssl->msg_callback_arg = strdup(inet_ntoa(addr.sin_addr)); // stash this real quick
        st_thread_create((void *)(void *)handle_connection, ssl, 0, STACKSIZE);
      }
    }
  }
}

