// ARP caching list

#include <stdio.h>
#include <netinet/in.h>
#include <sys/time.h>

typedef struct ARP_cache ARP_cache;

ARP_cache *addARPEntry(ARP_cache *head, uint32_t ip, uint8_t *mac);
uint8_t *getMAC(ARP_cache *head, uint32_t IP);
ARP_cache *removeExpired(ARP_cache *head);
void printCache(ARP_cache *head);

struct ARP_cache {
    uint32_t IP;
    uint8_t MAC[6];
    struct timeval tv;
    ARP_cache *next;
};
