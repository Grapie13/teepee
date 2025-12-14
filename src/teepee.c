#include <teepee/teepee.h>
#include <teepee/getipaddr.h>
#include <teepee/port.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/types.h>

int init_SSL(void);
void clean_up(SSL *ssl, SSL_CTX *ssl_ctx, const int *socket, teepee_ipaddrdata *ipaddrdata, const char *request);
teepee_error *construct_error(teepee_error_code code, const char *message);
teepee_result *construct_result(int ok, const char *body, const teepee_error *error);
teepee_result *construct_failure_result(const teepee_error *error);
teepee_result *construct_success_result(const char *body);
const char *teepee_method_to_string(method_t method);

teepee_result *teepee(const char *url, const teepee_opts *opts)
{
  if (url == NULL)
  {
    teepee_error *error = construct_error(NULL_URL, "URL cannot be NULL");
    return construct_failure_result(error);
  }

  int SSL_initialized = init_SSL();

  if (SSL_initialized < 0)
  {
    teepee_error *error = construct_error(SSL_INITIALIZATION_FAILURE, "Failed to initialize SSL");
    return construct_failure_result(error);
  }

  teepee_ipaddrdata *addr = getipaddr(url);

  if (addr == NULL)
  {
    teepee_error *error = construct_error(URL_TRANSLATION_FAILURE, "Failed to translate URL to IP address");
    return construct_failure_result(error);
  }

  int req_socket = socket(addr->ad_family, SOCK_STREAM, 0);

  if (req_socket < 0)
  {
    clean_up(NULL, NULL, &req_socket, addr, NULL);
    teepee_error *error = construct_error(SOCKET_CREATION_FAILURE, "Failed to create socket");
    return construct_failure_result(error);
  }

  int connection;

  if (addr->ad_family == AF_INET)
  {
    struct sockaddr_in *saddr = (struct sockaddr_in *)addr->addr;
    saddr->sin_port = htons(HTTPS);
    connection = connect(req_socket, (struct sockaddr *)saddr, sizeof(*saddr));
  }
  else
  {
    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr->addr;
    saddr->sin6_port = htons(HTTPS);
    connection = connect(req_socket, (struct sockaddr *)saddr, sizeof(*saddr));
  }

  if (connection < 0)
  {
    clean_up(NULL, NULL, &req_socket, addr, NULL);
    teepee_error *error = construct_error(CONNECTION_FAILURE, "Failed to establish connection with server");
    return construct_failure_result(error);
  }

  const SSL_METHOD *client_meth = TLS_client_method();
  SSL_CTX *ssl_ctx = SSL_CTX_new(client_meth);
  SSL *ssl = SSL_new(ssl_ctx);

  int ssl_set = SSL_set_fd(ssl, req_socket);

  if (!ssl_set)
  {
    clean_up(ssl, ssl_ctx, &req_socket, addr, NULL);
    teepee_error *error = construct_error(FD_FAILURE, "Failed to set file descriptor");
    return construct_failure_result(error);
  }

  int ssl_handshake = SSL_connect(ssl);

  if (!ssl_handshake)
  {
    clean_up(ssl, ssl_ctx, &req_socket, addr, NULL);
    teepee_error *error = construct_error(SSL_HANDSHAKE_FAILURE, "Failed to establish SSL handshake");
    return construct_failure_result(error);
  }

  const int INITIAL_REQUEST_SIZE = 256;
  int current_request_size = INITIAL_REQUEST_SIZE;
  char *request = malloc(sizeof(char) * INITIAL_REQUEST_SIZE);
  const char *method = "GET";
  const int INITIAL_HEADER_SIZE = 3;
  int header_size = INITIAL_HEADER_SIZE;
  teepee_header *headers = malloc(sizeof(teepee_header) * INITIAL_HEADER_SIZE);

  headers[0] = (teepee_header) {"Host", url};
  headers[1] = (teepee_header) {"User-Agent", "teepee/1.0"};
  headers[2] = (teepee_header) {"Connection", "close"};

  if (opts != NULL)
  {
    if (opts->method != NULL)
    {
      method = teepee_method_to_string(opts->method);
    }

    if (opts->headers != NULL)
    {
      teepee_header *tmp = headers;
      headers = realloc(headers, sizeof(teepee_header) * (INITIAL_HEADER_SIZE + opts->header_size));

      if (headers == NULL)
      {
        free(tmp);
        clean_up(ssl, ssl_ctx, &req_socket, addr, request);
        teepee_error *error = construct_error(ALLOCATION_FAILURE, "Failed to reallocate header size");
        return construct_failure_result(error);
      }

      for (int i = 0; i < opts->header_size; i++)
      {
        headers[i + INITIAL_HEADER_SIZE] = (teepee_header) {opts->headers[i].name, opts->headers[i].value};
      }

      header_size = header_size + opts->header_size;
    }
  }

  snprintf(request, current_request_size, "%s / HTTP/1.1\r\n", method);

  for (int i = 0; i < header_size; i++)
  {
    teepee_header header = headers[i];
    const int spacer_size = 4 + 1; // this takes into account ": " and "\r\n", as well as null byte
    const int header_size = spacer_size + strlen(header.name) + strlen(header.value);
    char header_string[header_size];

    snprintf(header_string, header_size, "%s: %s\r\n", header.name, header.value);

    if (strlen(request) + strlen(header_string) > current_request_size)
    {
      char *tmp = request;
      request = realloc(request, sizeof(char) * current_request_size + header_size + 1);

      if (request == NULL)
      {
        clean_up(ssl, ssl_ctx, &req_socket, addr, tmp);
        teepee_error *error = construct_error(ALLOCATION_FAILURE, "Failed to reallocate request size");
        return construct_failure_result(error);
      }

      current_request_size = current_request_size + header_size;
    }

    strcat(request, header_string);
  }

  const char *spacer = "\r\n";
  const int spacer_size = strlen(spacer);

  if (strlen(request) + spacer_size > current_request_size)
  {
    char *tmp = request;
    request = realloc(request, sizeof(char) * current_request_size + spacer_size + 1);

    if (request == NULL)
    {
      clean_up(ssl, ssl_ctx, &req_socket, addr, tmp);
      teepee_error *error = construct_error(ALLOCATION_FAILURE, "Failed to reallocate request size");
      return construct_failure_result(error);
    }

    current_request_size = current_request_size + spacer_size;
  }

  strcat(request, spacer);

  if (opts != NULL && opts->data != NULL)
  {
    printf("Writing data\n");
    const int data_size = strlen(opts->data);

    if (strlen(request) + data_size > current_request_size)
    {
      char *tmp = request;
      request = realloc(request, sizeof(char) * current_request_size + spacer_size + 1);

      if (request == NULL)
      {
        clean_up(ssl, ssl_ctx, &req_socket, addr, tmp);
        teepee_error *error = construct_error(ALLOCATION_FAILURE, "Failed to reallocate request size");
        return construct_failure_result(error);
      }

      current_request_size = current_request_size + spacer_size;
    }

    strcat(request, opts->data);
  }

  printf("%s", request);

  long bytes_sent = SSL_write(ssl, request, strlen(request));

  if (bytes_sent < 0)
  {
    clean_up(ssl, ssl_ctx, &req_socket, addr, request);
    teepee_error *error = construct_error(REQUEST_FAILURE, "Failed to send request");
    return construct_failure_result(error);
  }

  const int INITIAL_RESPONSE_SIZE = 64;
  char *response = malloc(sizeof(char) * INITIAL_RESPONSE_SIZE);

  if (response == NULL)
  {
    clean_up(ssl, ssl_ctx, &req_socket, addr, request);
    teepee_error *error = construct_error(ALLOCATION_FAILURE, "Failed to allocate response memory size");
    return construct_failure_result(error);
  }

  long bytes_received = 0;
  long total_bytes_received = 0;

  do
  {
    char part[256];

    bytes_received = SSL_read(ssl, part, sizeof(part));
    if (bytes_received > 0)
    {
      if (bytes_received + total_bytes_received > INITIAL_RESPONSE_SIZE)
      {
        char *tmp = response;
        response = realloc(response, sizeof(char) * (bytes_received + total_bytes_received));

        if (response == NULL)
        {
          free(tmp);
          clean_up(ssl, ssl_ctx, &req_socket, addr, request);
          teepee_error *error = construct_error(ALLOCATION_FAILURE, "Failed to reallocate response memory size");
          return construct_failure_result(error);
        }
      }

      memcpy(response + total_bytes_received, part, bytes_received);
      total_bytes_received += bytes_received;
    }
  } while (bytes_received > 0);

  response[total_bytes_received] = '\0';
  clean_up(ssl, ssl_ctx, &req_socket, addr, request);

  return construct_success_result(response);
}

void free_teepee_result(teepee_result *result)
{
  if (result == NULL)
  {
    return;
  }

  if (result->error != NULL)
  {
    free(result->error);
  }

  free(result);
}

int init_SSL(void)
{
  int SSL_initialized = SSL_library_init();
  int error_strings_loaded = SSL_load_error_strings();

  return SSL_initialized && error_strings_loaded;
}

void clean_up(SSL *ssl, SSL_CTX *ssl_ctx, const int *socket, teepee_ipaddrdata *ipaddrdata, const char *request)
{
  if (ssl != NULL)
  {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  if (ssl_ctx != NULL)
  {
    SSL_CTX_free(NULL);
  }

  if (socket != NULL)
  {
    close(*socket);
  }

  if (ipaddrdata != NULL)
  {
    free(ipaddrdata->addr);
    free(ipaddrdata);
  }

  if (request != NULL)
  {
    free(request);
  }
}

teepee_error *construct_error(teepee_error_code code, const char *message)
{
  teepee_error *error = malloc(sizeof(teepee_error));
  error->code = code;
  error->message = message;

  return error;
}

teepee_result *construct_result(int ok, const char* body, const teepee_error *error)
{
  teepee_result *result = malloc(sizeof(teepee_result));
  result->ok = ok;
  result->body = body;
  result->error = error;

  return result;
}

teepee_result *construct_failure_result(const teepee_error *error)
{
  return construct_result(EXIT_FAILURE, NULL, error);
}

teepee_result *construct_success_result(const char *body)
{
  return construct_result(EXIT_SUCCESS, body, NULL);
}

const char *teepee_method_to_string(method_t method)
{
  switch (method) {
    case CONNECT:
      return "CONNECT";
    case TRACE:
      return "TRACE";
    case OPTIONS:
      return "OPTIONS";
    case HEAD:
      return "HEAD";
    case GET:
      return "GET";
    case PUT:
      return "PUT";
    case PATCH:
      return "PATCH";
    case POST:
      return "POST";
    case DELETE:
      return "DELETE";
    default:
      return "GET";
  }
}