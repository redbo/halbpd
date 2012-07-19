#include <st.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <pwd.h>

#define BUFSIZE 16384
#define STACKSIZE (1024 * 32) // 32 kb is enough for anyone
#define TIMEOUT 60000000 // 60 seconds
#define BACKEND_CONNECT_TIMEOUT 5000000 // 2 seconds
#define DEFAULT_CONFIG_FILE "/etc/halbpd/config"
#define DEFAULT_CIPHER_LIST "AES128-SHA:AES:RC4:CAMELLIA128-SHA:!MD5:!ADH:!DH:!ECDH:!PSK:!SSLv2"
#define DEFAULT_CERT_FILE "/etc/halbpd/server.crt"
#define DEFAULT_KEY_FILE "/etc/halbpd/server.key"
#define DEFAULT_BACKEND "127.0.0.1:80"
#define DEFAULT_FRONTEND "0.0.0.0:443"
#define DEFAULT_SESSION_STORE "/dev/shm"
#define DEFAULT_USERNAME "root"
#define DEFAULT_PROXY_MODE "true"

typedef struct conndata {
  struct sockaddr addr;
  struct sockaddr_in *addr_in;
  SSL *ssl;
} conndata;

struct addrinfo *backend_sa;
struct addrinfo *frontend_sa;
int frontend_port;
int proxy_mode;

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

  if (st_connect(server_sock, backend_sa->ai_addr, backend_sa->ai_addrlen, BACKEND_CONNECT_TIMEOUT))
    goto cleanup;

  setsockopt(st_netfd_fileno(server_sock), IPPROTO_TCP, TCP_NODELAY, &size, sizeof(size));
  SSL_set_accept_state(data->ssl);

  void *client_to_server(void *arg)
  {
    char buffer[BUFSIZE], ipbuf[1024];
    int bufpos = 0, buflen = 0, wlen = 0;
    SSL *ssl = data->ssl;

    if (proxy_mode)
      buflen = snprintf(buffer, sizeof(buffer), "PROXY %s %s %s %u %u\r\n",
                        (data->addr.sa_family == AF_INET6) ? "TCP6" : "TCP4",
                        inet_ntop(data->addr_in->sin_family,
                          &data->addr_in->sin_addr, ipbuf, sizeof(ipbuf)),
                        inet_ntop(frontend_sa->ai_family,
                          &data->addr_in->sin_addr, ipbuf, sizeof(ipbuf)),
                        ntohs(data->addr_in->sin_port), frontend_port);

    do
    {
      for (bufpos = 0; (bufpos < buflen); bufpos += wlen)
      {
        wlen = st_write(server_sock, buffer + bufpos, buflen - bufpos, TIMEOUT);
        if (wlen <= 0)
          goto client_to_server_cleanup;
      }
    } while ((buflen = SSL_read(ssl, buffer, sizeof(buffer))) > 0);

    client_to_server_cleanup:
      st_thread_interrupt(s2c);
      return NULL;
  }

  void *server_to_client(void *arg)
  {
    char buffer[BUFSIZE];
    int bufpos = 0, buflen = 0, wlen = 0;
    SSL *ssl = data->ssl;

    while ((buflen = st_read(server_sock, buffer, sizeof(buffer), TIMEOUT)) > 0)
    {
      for (bufpos = 0; (bufpos < buflen); bufpos += wlen)
      {
        wlen = SSL_write(ssl, buffer + bufpos, buflen - bufpos);
        if (wlen <= 0)
          goto server_to_client_cleanup;
      }
    }
    server_to_client_cleanup:
      st_thread_interrupt(c2s);
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
  fclose(fp);
  if (processors > 0 && processors <= 128)
    return processors * 2;
  return 16;
}

long hash_id(unsigned char *id, int length)
{
  unsigned long a = 1, b = 0, index = 0;
  for (; (index < length); index++)
  {
    a = (a + id[index]) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}

struct addrinfo *populate_sa(char *address)
{
  char hostname[256], service[256];
  if (sscanf(address, " [%[0-9a-fA-F:]] : %s ", hostname, service) ||
      sscanf(address, " %[0-9.] : %s ", hostname, service))
  {
    struct addrinfo hints, *res;
    memset(&hints, '\0', sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    printf("%s : %s\n", hostname, service);
    if (!getaddrinfo(hostname, service, &hints, &res) && res)
      return res;
  }
  return NULL;
}

SSL_CTX *ssl_init(char *cert, char *key, char *cipher_list)
{
  SSL_CTX *ctx;
  SSL_library_init();
  SSL_load_error_strings();

  if (!(ctx = SSL_CTX_new(SSLv23_server_method())) ||
      !SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_ALL) ||
      !SSL_CTX_set_cipher_list(ctx, cipher_list) ||
      (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) ||
      (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0))
  {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "cipherlist: %s\n", cipher_list);
    fprintf(stderr, "cert file: %s\n", cert);
    fprintf(stderr, "key file: %s\n", key);
    return NULL;
  }
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  return ctx;
}

int main(int argc, char **argv)
{
  char *config_file = DEFAULT_CONFIG_FILE;
  char frontend[1024] = DEFAULT_FRONTEND;
  char cipher_list[1024] = DEFAULT_CIPHER_LIST;
  char rsa_server_cert[1024] = DEFAULT_CERT_FILE;
  char rsa_server_key[1024] = DEFAULT_KEY_FILE;
  char backend[1024] = DEFAULT_BACKEND;
  char username[1024] = DEFAULT_USERNAME;
  char proxymode[1024] = DEFAULT_PROXY_MODE;
  int listen_sock, process_count = 0;
  SSL_CTX *ctx;
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

  if (argc > 1)
    config_file = argv[1];
  FILE *fp = fopen(config_file, "r");
  if (fp)
  {
    char line[1024];
    while (fgets(line, sizeof(line), fp))
    {
      sscanf(line, " cert = %s ", rsa_server_cert);
      sscanf(line, " key = %s ", rsa_server_key);
      sscanf(line, " workers = %d ", &process_count);
      sscanf(line, " ciphers = %s ", cipher_list);
      sscanf(line, " frontend = %s ", frontend);
      sscanf(line, " backend = %s ", backend);
      sscanf(line, " username = %s ", username);
      sscanf(line, " proxymode = %s ", proxymode);
    }
  }
  else
  {
    fprintf(stderr, "Unable to find config file %s\n"
                    "It should look like:\n"
                    "    # workers = 0\n"
                    "    # ciphers = " DEFAULT_CIPHER_LIST "\n"
                    "    # frontend = " DEFAULT_FRONTEND "\n"
                    "    # backend = " DEFAULT_BACKEND "\n"
                    "    # username = " DEFAULT_USERNAME "\n"
                    "    # proxymode = " DEFAULT_PROXY_MODE "\n"
                    "    cert = " DEFAULT_CERT_FILE "\n"
                    "    key = " DEFAULT_KEY_FILE "\n", config_file);
    return 1;
  }

  backend_sa = populate_sa(backend);
  frontend_sa = populate_sa(frontend);
  if (frontend_sa->ai_family == AF_INET)
    frontend_port = ntohs(((struct sockaddr_in*)frontend_sa->ai_addr)->sin_port);
  else
    frontend_port = ntohs(((struct sockaddr_in6*)frontend_sa->ai_addr)->sin6_port);

  if (!(ctx = ssl_init(rsa_server_cert, rsa_server_key, cipher_list)))
    return 1;

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

  if (bind(listen_sock, frontend_sa->ai_addr, frontend_sa->ai_addrlen) != 0)
  {
    perror("bind");
    return 1;
  }

  if (listen(listen_sock, SOMAXCONN) < 0)
  {
    perror("listen");
    return 1;
  }

  proxy_mode = !strcasecmp(proxymode, "true") || !strcasecmp(proxymode, "t") ||
               !strcasecmp(proxymode, "on") || !strcasecmp(proxymode, "enabled");

  struct passwd *pw = getpwnam(username);
  if (pw)
  {
    setuid(pw->pw_uid);
    setgid(pw->pw_gid);
  }

  umask(077);

  if (!process_count)
    process_count = default_process_count();
  fprintf(stderr, "Starting up %d processes.\n", process_count);
  fprintf(stderr, "Proxy mode: %s\n", proxy_mode ? "enabled" : "disabled");

  if (daemon(0, 0) < 0)
  {
    perror("daemon");
    return 1;
  }

  while (--process_count)
  {
    pid_t pid;
    if (!(pid = fork()))
      break;
    if (pid < 0)
      return 1;
  }

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

