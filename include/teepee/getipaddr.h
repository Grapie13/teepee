#ifndef GETIPADDR_H
#define GETIPADDR_H

typedef struct teepee_ipaddrdata
{
    int ad_family;
    void *addr;
} teepee_ipaddrdata;

struct teepee_ipaddrdata *getipaddr(const char *hostname);

#endif