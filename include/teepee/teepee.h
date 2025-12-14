#ifndef TEEPEE_H
#define TEEPEE_H

typedef enum method_t
{
  CONNECT,
  TRACE,
  OPTIONS,
  HEAD,
  GET,
  PUT,
  PATCH,
  POST,
  DELETE
} method_t;

typedef enum teepee_error_code
{
  NULL_URL = -1,
  SSL_INITIALIZATION_FAILURE = -2,
  URL_TRANSLATION_FAILURE = -3,
  SOCKET_CREATION_FAILURE = -4,
  CONNECTION_FAILURE = -5,
  FD_FAILURE = -6,
  SSL_HANDSHAKE_FAILURE = -7,
  REQUEST_FAILURE = -8,
  ALLOCATION_FAILURE = -9
} teepee_error_code;

typedef struct teepee_header
{
  const char *name;
  const char *value;
} teepee_header;

typedef struct teepee_opts
{
  method_t method;
  teepee_header *headers;
  int header_size;
  const char *data;
  int secure;
} teepee_opts;

typedef struct teepee_error
{
  int code;
  const char *message;
} teepee_error;

typedef struct teepee_result
{
  int ok;
  const char *body;
  const teepee_error *error;
} teepee_result;

teepee_result *teepee(const char *url, const teepee_opts *opts);
void free_teepee_result(teepee_result *result);

#endif