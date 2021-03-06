#include <st.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <pwd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>

#define BUFSIZE 32768
#define STACKSIZE (1024 * 8) // 8 kb is enough for anyone
#define TIMEOUT 120000000 // 120 seconds
#define LISTEN_QUEUE 1024
#define BACKEND_CONNECT_TIMEOUT 10000000 // 10 seconds
#define DEFAULT_CONFIG_FILE "/etc/halbpd/config"
#define DEFAULT_CIPHER_LIST "AES128-SHA:AES:RC4:CAMELLIA128-SHA:!MD5:!ADH:!DH:!ECDH:!PSK:!SSLv2"
#define DEFAULT_CERT_FILE "/etc/halbpd/server.crt"
#define DEFAULT_KEY_FILE "/etc/halbpd/server.key"
#define DEFAULT_BACKEND "127.0.0.1:80"
#define DEFAULT_FRONTEND "0.0.0.0:443"
#define DEFAULT_SESSION_STORE "/dev/shm"
#define DEFAULT_USERNAME "root"
#define DEFAULT_PROXY_MODE "enabled"
#define MAX_FILES 16384

#define CHECKRESPONSE(x, y) if ((y) < 0) {perror((x));exit(1);}

typedef struct conndata {
  struct sockaddr_in *addr_in;
  SSL *ssl;
  struct conndata *next;
  char c2sbuf[BUFSIZE];
  char s2cbuf[BUFSIZE];
  struct sockaddr addr;
} conndata;

struct addrinfo *backend_sa, *frontend_sa;
int frontend_port;
int haproxy_mode;
conndata *conndata_list = NULL;

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
  st_thread_t c2s, s2c;
  SSL *ssl = data->ssl;
  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock < 0)
    return NULL;

  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &size, sizeof(size));

  st_netfd_t server_sock = st_netfd_open_socket(sock);

  if (!server_sock)
    goto cleanup;

  if (st_connect(server_sock, backend_sa->ai_addr, backend_sa->ai_addrlen, BACKEND_CONNECT_TIMEOUT))
    goto cleanup;

  SSL_set_accept_state(data->ssl);

  void *client_to_server(void *arg)
  {
    char *buffer = data->c2sbuf;
    char ipbuf[48];
    int bufpos = 0, buflen = 0, wlen = 0;

    if (haproxy_mode)
      buflen = snprintf(buffer, BUFSIZE, "PROXY %s %s %s %u %u\r\n",
                        (data->addr.sa_family == AF_INET6) ? "TCP6" : "TCP4",
                        inet_ntop(data->addr_in->sin_family,
                          &data->addr_in->sin_addr, ipbuf, sizeof(ipbuf)),
                        inet_ntop(frontend_sa->ai_family,
                          &data->addr_in->sin_addr, ipbuf, sizeof(ipbuf)),
                        ntohs(data->addr_in->sin_port), frontend_port);

    if ((wlen = SSL_read(ssl, buffer + buflen, BUFSIZE - buflen)) < 0)
      goto client_to_server_cleanup;
    buflen += wlen;
    do
    {
      for (bufpos = 0; (bufpos < buflen); bufpos += wlen)
      {
        if ((wlen = st_write(server_sock, buffer + bufpos, buflen - bufpos, TIMEOUT)) < 0)
          goto client_to_server_cleanup;
      }
    }
    while ((buflen = SSL_read(ssl, buffer, BUFSIZE)) > 0);

    client_to_server_cleanup:
      st_thread_interrupt(s2c);
      return NULL;
  }

  void *server_to_client(void *arg)
  {
    char *buffer = data->s2cbuf;
    int bufpos = 0, buflen = 0, wlen = 0;

    while ((buflen = st_read(server_sock, buffer, BUFSIZE, TIMEOUT)) > 0)
    {
      for (bufpos = 0; (bufpos < buflen); bufpos += wlen)
      {
        if ((wlen = SSL_write(ssl, buffer + bufpos, buflen - bufpos)) < 0)
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
    data->next = conndata_list;
    conndata_list = data;

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
    return processors;
  return 16;
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
    if (!getaddrinfo(hostname, service, &hints, &res) && res)
      return res;
  }
  return NULL;
}

#define CHECKSSL(x) if (x) {ERR_print_errors_fp(stderr); exit(1);}
SSL_CTX *ssl_init(char *cert, char *key, char *cipher_list)
{
  SSL_CTX *ctx;
  SSL_library_init();
  SSL_load_error_strings();

  CHECKSSL(!(ctx = SSL_CTX_new(SSLv23_server_method())))
  CHECKSSL(!SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_ALL))
  CHECKSSL(!SSL_CTX_set_cipher_list(ctx, cipher_list))
  CHECKSSL(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
  CHECKSSL(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  ENGINE_load_builtin_engines();
  ENGINE_register_all_complete();
  ENGINE *e = ENGINE_by_id("aesni");
  if (e)
  {
    ENGINE_init(e);
    ENGINE_ctrl_cmd_string(e, "THREAD_LOCKING", "0", 0);
    ENGINE_ctrl_cmd_string(e, "FORK_CHECK", "0", 0);
    ENGINE_set_default_RSA(e);
    ENGINE_set_default_DSA(e);
    ENGINE_set_default(e, ENGINE_METHOD_ALL);
  }
  else
    fprintf(stderr, "Unable to load aesni engine.\n");
  return ctx;
}

int is_enabled(char *setting)
{
  char *truthy[] = {"true", "t", "on", "enabled", 0};
  int i = 0;
  for (i = 0; truthy[i]; i++)
    if (!strcasecmp(truthy[i], setting))
      return 1;
  return 0;
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
  int listen_sock = 0, process_count = 0, sockopt = 1;
  struct passwd *pw = NULL;
  SSL_CTX *ctx = NULL;
  st_netfd_t listener = NULL, client = NULL;
  FILE *fp = NULL;
  struct rlimit rl = {MAX_FILES, MAX_FILES};

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
  if ((fp = fopen(config_file, "r")))
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
      sscanf(line, " haproxymode = %s ", proxymode);
    }
  }
  else
  {
    fprintf(stderr, "Unable to find config file %s\n"
                    "It should look like:\n"
                    "    workers = 0\n"
                    "    ciphers = " DEFAULT_CIPHER_LIST "\n"
                    "    frontend = " DEFAULT_FRONTEND "\n"
                    "    backend = " DEFAULT_BACKEND "\n"
                    "    username = " DEFAULT_USERNAME "\n"
                    "    haproxymode = " DEFAULT_PROXY_MODE "\n"
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

  haproxy_mode = is_enabled(proxymode);

  if (!process_count)
    process_count = default_process_count();

  umask(077);

  mlockall(MCL_CURRENT | MCL_FUTURE);

  if (setrlimit(RLIMIT_NOFILE, &rl))
    perror("Increasing fileno ulimit - requires root");

  CHECKRESPONSE("socket", listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP))
  CHECKRESPONSE("setsockopt", setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &sockopt, sizeof(sockopt)))
  CHECKRESPONSE("bind", bind(listen_sock, frontend_sa->ai_addr, frontend_sa->ai_addrlen))
  CHECKRESPONSE("listen", listen(listen_sock, LISTEN_QUEUE))

  if ((pw = getpwnam(username)))
  {
    CHECKRESPONSE("setuid", setuid(pw->pw_uid))
    CHECKRESPONSE("setgid", setgid(pw->pw_gid))
  }

  CHECKRESPONSE("daemon", daemon(0, 0))

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
    int adlen, client_sock, size;
    conndata *data;

    if (conndata_list)
    {
      data = conndata_list;
      conndata_list = data->next;
    }
    else
      data = (conndata *)malloc(sizeof(conndata));
    adlen = sizeof(data->addr);
    if ((client = st_accept(listener, (struct sockaddr*)&(data->addr), &adlen, TIMEOUT)))
    {
      data->addr_in = (struct sockaddr_in *)&(data->addr);
      client_sock = st_netfd_fileno(client);
      size = 1;
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

