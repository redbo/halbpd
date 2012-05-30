#include <st.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFSIZE 16384
#define STACKSIZE (1024 * 32) // 32 kb is enough for anyone
#define TIMEOUT 30000000 // 30 seconds
#define BACKEND_TIMEOUT 5000000 // 2 seconds
#define ERROR_OUT 60

typedef struct conndata {
  struct sockaddr addr;
  struct sockaddr_in *addr_in;
  SSL *ssl;
} conndata;

struct sockaddr_in backend_sa;
struct sockaddr_in server_sa;

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

static int stb_read(BIO *b, char *out, int len)
{
  return st_read((st_netfd_t)b->ptr, out, len, TIMEOUT);
}

static int stb_write(BIO *b, const char *str, int len)
{
  return st_write((st_netfd_t)b->ptr, str, len, TIMEOUT);
}

static int stb_puts(BIO *b, const char *str)
{
  return st_write((st_netfd_t)b->ptr, str, strlen(str), TIMEOUT);
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
        ip = (int *)ptr;
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
    default:
      return 0;
  }
}

void *handle_connection(conndata *data)
{
  int size = 1;
  st_thread_t c2s;
  st_thread_t s2c;

  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock < 0)
    return NULL;

  st_netfd_t server_sock = st_netfd_open_socket(sock);

  if (!server_sock)
    goto cleanup;

  if (st_connect(server_sock, (struct sockaddr *)(&backend_sa), sizeof(backend_sa), BACKEND_TIMEOUT))
    goto cleanup;

  setsockopt(st_netfd_fileno(server_sock), IPPROTO_TCP, TCP_NODELAY, &size, sizeof(size));
  SSL_set_accept_state(data->ssl);

  void *client_to_server(void *arg)
  {
    char buffer[BUFSIZE], ipbuf[1024];
    int bufpos = 0, buflen = 0, wlen = 0;
    SSL *ssl = data->ssl;

    buflen = snprintf(buffer, sizeof(buffer), "PROXY %s %s %s %u %u\r\n",
            (data->addr.sa_family == AF_INET6) ? "TCP6" : "TCP4",
            inet_ntop(data->addr_in->sin_family, &data->addr_in->sin_addr, ipbuf, sizeof(ipbuf)),
            inet_ntop(server_sa.sin_family, &data->addr_in->sin_addr, ipbuf, sizeof(ipbuf)),
            ntohs(data->addr_in->sin_port),
            ntohs(server_sa.sin_port));

    do
    {
      bufpos = 0;
      while (bufpos < buflen)
      {
        wlen = st_write(server_sock, buffer + bufpos, buflen - bufpos, TIMEOUT);
        if (wlen <= 0)
          goto client_to_server_cleanup;
        bufpos += wlen;
      }
    } while ((buflen = SSL_read(ssl, buffer, BUFSIZE)) > 0);

    client_to_server_cleanup:
      st_thread_interrupt(s2c);
      return NULL;
  }

  void *server_to_client(void *arg)
  {
    char buffer[BUFSIZE];
    int bufpos = 0, buflen = 0, wlen = 0;
    SSL *ssl = data->ssl;

    while ((buflen = st_read(server_sock, buffer + buflen, sizeof(buffer) - buflen, TIMEOUT)) > 0)
    {
      bufpos = 0;
      while (bufpos < buflen)
      {
        wlen = SSL_write(ssl, buffer, buflen);
        if (wlen <= 0)
          goto server_to_client_cleanup;
        bufpos += wlen;
      }
    }
    server_to_client_cleanup:
      st_thread_interrupt(s2c);
      return NULL;
  }

  c2s = st_thread_create(client_to_server, NULL, 1, STACKSIZE);
  if (c2s)
  {
    s2c = st_thread_create(server_to_client, NULL, 1, STACKSIZE);
    st_thread_join(c2s, NULL);
    st_thread_join(s2c, NULL);
  }

  cleanup:
    SSL_shutdown(data->ssl);
    SSL_free(data->ssl);
    if (server_sock)
      st_netfd_close(server_sock);
    free(data);

  return NULL;
}

int default_process_count()
{
  FILE *fp = fopen("/proc/cpuinfo", "r");
  char buf[1024];
  int processors = 0;
  while (fgets(buf, sizeof(buf), fp))
  {
    if (!strncmp(buf, "processor\t", 10))
      processors++;
  }
  fprintf(stderr, "Starting up %d processes.\n", processors);
  fclose(fp);
  if (processors > 0 && processors <= 128)
    return processors * 2;
  return 16;
}

int main(int argc, char **argv)
{
  int s_port = 443;
  // "RC4-MD5:RC4-SHA:RC4:MD5:SHA:ALL"
  char cipher_list[1024] = "AES256-SHA:AES128-SHA:ALL";
  char rsa_server_cert[1024] = "/etc/halbpd/server.crt";
  char rsa_server_key[1024] = "/etc/halbpd/server.key";
  char backend[1024] = "127.0.0.1:80";
  int listen_sock, process_count = 0;
  SSL_CTX *ctx;
  st_netfd_t listener, client;
  char ip[16];
  int port;

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

  FILE *fp = fopen("/etc/halbpd/conf", "r");
  if (fp)
  {
    char line[1024];
    while (fgets(line, sizeof(line), fp))
    {
      sscanf(line, " cert = %s ", rsa_server_cert);
      sscanf(line, " key = %s ", rsa_server_key);
      sscanf(line, " port = %d ", &s_port);
      sscanf(line, " workers = %d ", &process_count);
      sscanf(line, " ciphers = %s ", cipher_list);
      sscanf(line, " backend = %[^\n] ", backend);
    }
  }
  else
  {
    fprintf(stderr, "Expected to find /etc/halbpd/conf like:\n"
                    " # workers = 0\n"
                    " # port = 443\n"
                    " # ciphers = AES256-SHA:AES128-SHA:SHA1:ALL\n"
                    " cert = /etc/halbpd/server.crt\n"
                    " key = /etc/halbpd/server.key\n"
                    " backend = 127.0.0.1:80\n");
    return 1;
  }

  if (sscanf(backend, " %[^:] : %d ", ip, &port))
  {
    memset(&backend_sa, '\0', sizeof(server_sa));
    backend_sa.sin_family = AF_INET;
    backend_sa.sin_addr.s_addr = inet_addr(ip);
    backend_sa.sin_port = htons(port);
  }

  SSL_library_init();
  SSL_load_error_strings();

  if (!(ctx = SSL_CTX_new(SSLv23_server_method())) ||
      !SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_ALL) ||
      !SSL_CTX_set_cipher_list(ctx, cipher_list) ||
      (SSL_CTX_use_certificate_file(ctx, rsa_server_cert, SSL_FILETYPE_PEM) <= 0) ||
      (SSL_CTX_use_PrivateKey_file(ctx, rsa_server_key, SSL_FILETYPE_PEM) <= 0))
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

  memset(&server_sa, '\0', sizeof(server_sa));
  server_sa.sin_family = AF_INET;
  server_sa.sin_addr.s_addr = INADDR_ANY;
  server_sa.sin_port = htons(s_port);

  if (bind(listen_sock, (struct sockaddr*)&server_sa, sizeof(server_sa)) < 0)
  {
    perror("bind");
    return 1;
  }

  if (listen(listen_sock, SOMAXCONN) < 0)
  {
    perror("bind");
    return 1;
  }

  if (!process_count)
    process_count = default_process_count();
  while (--process_count)
  {
    if (!fork())
      break;
  }

  if (fork()) // daemonize
    return 0;
  setsid();

  st_init();
  #if defined(ST_EVENTSYS_ALT)
  st_set_eventsys(ST_EVENTSYS_ALT);
  #endif
  st_randomize_stacks(1);
  listener = st_netfd_open_socket(listen_sock);

  for (;;)
  {
    conndata *data = (conndata *)malloc(sizeof(conndata));
    int adlen = sizeof(data->addr);
    if ((client = st_accept(listener, (struct sockaddr*)&(data->addr), &adlen, TIMEOUT)))
    {
      data->addr_in = (struct sockaddr_in *)&(data->addr);
      int client_sock = st_netfd_fileno(client);
      int size = 1;
      st_netfd_free(client);
      setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &size, sizeof(size));
      if (client_sock >= 0)
      {
        data->ssl = SSL_new(ctx);
        BIO *ret = BIO_new(&methods_stbp);
        BIO_set_fd(ret, client_sock, 1);
        SSL_set_bio(data->ssl, ret, ret);
        st_thread_create((void *)(void *)handle_connection, data, 0, STACKSIZE);
      }
    }
  }
}

