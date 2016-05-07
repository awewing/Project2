// arp

#include "arp.h"
#include <stdio.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdlib.h>

ARP_cache *addARPEntry(ARP_cache *head, uint32_t ip, uint8_t *mac) {
    // check if entry is already there
    ARP_cache *curr = head;
    ARP_cache *prev = NULL;
    while (curr != NULL) {
        // Look for an entry already there
        if (curr->IP == ip) {
            // already here reinitialize the cache entry
            // if mac and ip dont match, replace mac
            for (int i = 0; i < 6; i++) {
                curr->MAC[i] = mac[i];
            }
            // set timeval
            gettimeofday(&curr->tv, NULL);

            // exit method
            return head;
        }

        prev = curr;
        curr = curr->next;
    }

    // No such entry, add new entry to end of list
    ARP_cache *newEntry = (ARP_cache *)malloc(sizeof(ARP_cache));
    newEntry->IP = ip;
    for (int i = 0; i < 6; i++) {
        newEntry->MAC[i] = mac[i];
    }
    gettimeofday(&newEntry->tv, NULL);

    if (prev == NULL) {
        // head was null to beginwith
        return newEntry;
    } else {
        prev->next = newEntry;
        return head;
    }
}

/*
 * Retreives mac. Returns -1 if not in list
 */
uint8_t *getMAC(ARP_cache *head, uint32_t IP) {
    // Look up mac
    ARP_cache *curr = head;
    while (curr != NULL) {
        if (curr->IP == IP) {
            // found correct entry
            return curr->MAC;
        }
        curr = curr->next;
    }
    return 0;
}

/*
 * Remove expired nodes in list
 */
ARP_cache *removeExpired(ARP_cache *head) {
    ARP_cache *curr = head;
    ARP_cache *prev = NULL;
    struct timeval time;
    gettimeofday(&time, NULL);

    while (curr != NULL) {
        if (time.tv_sec - curr->tv.tv_sec >= 15) {
            if (prev == NULL) {
                head = curr->next;
                free(curr);
                curr = head;
            } else {
                prev->next = curr->next;
                free(curr);
                curr = prev->next;
            }
        } else {
            prev = curr;
            curr = curr->next;
        }
    }
    return head;
}

void printCache(ARP_cache *head) {
	ARP_cache *curr = head;
	printf("head --> ");
	while(curr != NULL) {
		printf("%d --> ", curr->IP);
		curr = curr->next;		
	}
	printf("END\n");
}
