#include <teepee/getipaddr.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>

teepee_ipaddrdata *getipaddr(const char *hostname) {
  struct addrinfo hints, *res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
    freeaddrinfo(res);
    return NULL;
  }

  if (res) {
    teepee_ipaddrdata *addr = malloc(sizeof(*addr));

    if (res->ai_family == AF_INET) {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *) res->ai_addr;
      addr->ad_family = AF_INET;
      addr->addr = malloc(sizeof(*ipv4));
      memcpy(addr->addr, ipv4, sizeof(*ipv4));
    } else {
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) res->ai_addr;
      addr->ad_family = AF_INET6;
      addr->addr = malloc(sizeof(*ipv6));
      memcpy(addr->addr, ipv6, sizeof(*ipv6));
    }

    freeaddrinfo(res);

    return addr;
  }

  freeaddrinfo(res);

  return 0;
}