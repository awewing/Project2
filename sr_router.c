/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp.h"

void parseEthernetHeader(uint8_t * packet, unsigned char* dAddress, unsigned char* sAddress, uint16_t* type);
uint16_t handleARPPacket(uint8_t * packet, unsigned char* hwAddr, unsigned char* buffer);
void print_bytes(const void *object, size_t size);
void add32BitToMsg(unsigned char *msg, uint32_t num, int index);
void add16BitToMsg(unsigned char *msg, uint16_t num, int index);
uint16_t cksumAlg(uint16_t *buf, int count);
uint8_t getIPHeaderLength(uint8_t * ipPacket);
void updateChkSum(uint8_t ipHL, uint8_t *ipHeader);
void add8BitToMsg(unsigned char *msg, uint8_t num, int index);
uint32_t getNextHopIP(struct sr_rt* rt, uint32_t destIP, char * gatewayInterface);
ARP_cache * cache = NULL;
void createARPRequest(unsigned char * buffer, uint32_t gatewayIP, struct sr_if * interface);
void printIntAsIP(uint32_t ipInt);

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    int offset = 0;
    
    struct sr_if* iface = sr_get_interface(sr, interface);
    
    unsigned char dAddress[6 * sizeof(uint8_t)];
    unsigned char sAddress[6 * sizeof(uint8_t)];
    uint16_t type = -1;
    //print_bytes(packet, len);
    //printf("Whole packet %x")
    parseEthernetHeader(packet, dAddress, sAddress, &type);
    if (type == 2054){ //IS type ARP
        print_bytes(packet, 42);
        unsigned char replyARP[28];
        memset(replyARP, '\0', 28);
        int opCode = handleARPPacket(packet + sizeof(char) * 14, iface->addr, replyARP);
        if (opCode == 1){
        printf("Received ARP request.\n");
        unsigned char replyMsg[42];
        offset = 0;
        memcpy(&replyMsg, (void *)sAddress, 6 *sizeof(uint8_t));
        offset = offset + 6 *sizeof(uint8_t);
        memcpy(&replyMsg[offset], (void *)iface->addr, 6 * sizeof(uint8_t));
        offset = offset + 6 *sizeof(uint8_t);
        memcpy(&replyMsg[offset], (void *) packet + offset, 2 * sizeof(uint8_t));
        offset = offset + 2 *sizeof(uint8_t);
        memcpy(&replyMsg[offset], replyARP, 28);
        //print_bytes(replyMsg, 42);
        sr_send_packet(sr, replyMsg, 42, interface);
        }
        else{
            printf("Received ARP reply.\n");
        }
    }
    else if (type == 2048){//Type is IPv4
        int dropPacketFlag = 0;
        uint8_t forwardPacket[len];
        memcpy(&forwardPacket, (void *) packet, len);
        uint8_t * ipPacket = forwardPacket + sizeof(uint8_t) * 14;
        //Is IP destination the same as the router?
        int Bit32Size = sizeof(uint32_t);
        uint8_t ipDest[Bit32Size];
        memset(ipDest, 0, Bit32Size);
        memcpy(&ipDest[0], (void *) forwardPacket + sizeof(uint8_t) * 30, Bit32Size);
        uint32_t ipDestInt = *(uint32_t *)ipDest;
        printf("ifaceIP: ");
        printIntAsIP(iface->ip);
        printf("ipDest: ");
        printIntAsIP(ipDestInt);
        if (ipDestInt == iface->ip){
            dropPacketFlag = 1;
        }
        //Check and decrement the TTL
        char ttlTemp[sizeof(uint8_t)];
        memcpy(ttlTemp, (void *)forwardPacket + sizeof(uint8_t) * 22, sizeof(uint8_t));
        //uint8_t ttl = ntohs(*(uint8_t *) ttlTemp);
        uint8_t ttl = *(uint8_t *) ttlTemp;
        printf("TTL: %d\n", ttl);
        ttl = ttl - 1;
        if (ttl < 1){
            dropPacketFlag = 1;
        }
        else{
            add8BitToMsg(forwardPacket, ttl, sizeof(uint8_t) * 22);
        }
        //update IP checksum field
        //Get IP header length
        uint8_t ipHL = getIPHeaderLength(ipPacket);
        printf("IPHL %d\n", ipHL);
        //End of IP header length

        //Checking that cksum algorithm works
        //char ckTemp[sizeof(uint16_t)];
        //memcpy(ckTemp, (void *) packet + sizeof(uint8_t) * 24, sizeof(uint16_t));
        //uint16_t ckCompare = *(uint16_t *) ckTemp;
        //printf("cksumSentIn: %d\n", ckCompare);
        if (dropPacketFlag == 0){ 

        char * gatewayIF = NULL;
        uint32_t gatewayIP = getNextHopIP(sr->routing_table, ipDestInt, gatewayIF);
        uint8_t * gatewayMAC = getMAC(cache, gatewayIP);
        if (gatewayMAC == NULL){
            struct sr_if * ilist = sr->if_list;
            while (ilist != NULL){
                unsigned char requestARP[42];
                createARPRequest(requestARP + sizeof(uint8_t) * 14, gatewayIP, ilist);
               
                offset = 0;
                //memcpy(&requestARP, (void *)ilist->addr, 6 *sizeof(uint8_t));
                //memcpy(&requestARP[offset], "\xFFFFFFFFFFFF", 6 * sizeof(uint8_t));
                add32BitToMsg(requestARP, 4294967295, offset);
                offset = offset + 4 * sizeof(uint8_t);
                add16BitToMsg(requestARP, 65535, offset);
                offset = offset + 2 *sizeof(uint8_t);
                memcpy(&requestARP[offset], (void *)ilist->addr, 6 * sizeof(uint8_t));
                offset = offset + 6 *sizeof(uint8_t);
                add16BitToMsg(requestARP, 2054, offset);
                printf("Sending ARPRequest\n");
                print_bytes(requestARP, 42);
                sr_send_packet(sr, requestARP, 42, ilist->name); 
                ilist = ilist->next;
            }
            
            //send ARP Request, drop packet.
            dropPacketFlag = 1;
        }

        if (dropPacketFlag == 0){            
            updateChkSum(ipHL, ipPacket);
            memcpy(&forwardPacket + sizeof(uint8_t) * 6, (void *)iface->addr, 6 * sizeof(uint8_t));
            memcpy(&forwardPacket, (void *)gatewayMAC, 6 * sizeof(uint8_t));
            sr_send_packet(sr, forwardPacket, len, interface);
        }
        }   
    }
    //Check ARP cache entries each time to see if they are over 15 seconds old.
    printf("*** -> Received packet of length %d \n",len);
    cache = removeExpired(cache); 
    printf("\n\n-------------------------------------\n\n");
}/* end sr_ForwardPacket */

void updateChkSum(uint8_t ipHL, uint8_t *ipHeader){
    uint16_t buf[ipHL * 2];
    uint8_t ipHL16Bit = ipHL * 2;
    memset(buf, 0, sizeof(uint16_t) * ipHL16Bit);
    memcpy(buf, (void *) ipHeader, sizeof(uint16_t) * ipHL16Bit);
    memset(&buf[5], 0, sizeof(uint16_t));
    //print_bytes(buf, sizeof(uint16_t) * ipHL16Bit);
    uint16_t cksum = cksumAlg(buf, ipHL16Bit);
    add16BitToMsg(ipHeader, cksum, sizeof(uint8_t) * 10);
    //print_bytes(ipHeader, sizeof(uint16_t) * ipHL16Bit);
    printf("calculatedChk: %d\n", cksum);
}

uint8_t getIPHeaderLength(uint8_t *ipPacket) {
    char ipHLTemp[sizeof(uint8_t)];
    memcpy(ipHLTemp, (void *) ipPacket, sizeof(uint8_t));
    //print_bytes(ipHLTemp, sizeof(uint8_t));
    return *(uint8_t*)ipHLTemp& 0x0F;
}

uint16_t cksumAlg(uint16_t *buf, int count) {
    register uint32_t sum = 0;

    while(count--) {
        sum += *buf++;
        if (sum & 0xFFFF0000) {
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}

uint32_t getNextHopIP(struct sr_rt* rt, uint32_t destIP, char * gatewayInterface){
    if (rt == NULL){
        printf("ERROR: routing table is NULL\n\n\n\n");
    }
    uint32_t defaultGateway = rt->gw.s_addr;
    gatewayInterface = rt->interface;
    struct sr_rt* curr = rt->next;
    while (curr != NULL){
        if ((curr->mask.s_addr & destIP) == curr->dest.s_addr){
            gatewayInterface = curr->interface;
            printf(curr->gw.s_addr);
            if (curr->gw.s_addr == 0){
                return curr->dest.s_addr;
            }
            return curr->gw.s_addr;
        }
        curr = curr->next;
    }
    return defaultGateway;
}

void parseEthernetHeader(uint8_t * packet, unsigned char* dAddress, unsigned char* sAddress, uint16_t* type){
    int offset = 0;
    memcpy(dAddress, (void *)packet, 6 * sizeof(uint8_t));
    offset = offset + (sizeof(uint8_t) * 6);
    memcpy(sAddress, (void *)packet + offset, 6 * sizeof(uint8_t));
    offset = offset + (sizeof(uint8_t) * 6);
    char tempType[sizeof(uint8_t) * 2];
    memcpy(tempType, (void *)packet + offset, sizeof(uint8_t) * 2);
    *type = ntohs(*(int16_t *) tempType);
}

uint16_t handleARPPacket(uint8_t * packet, unsigned char* hwAddr, unsigned char* buffer) {
    unsigned char hardwareType[2];
    unsigned char protocolType[2];
    unsigned char hardwareAddr[1];
    unsigned char protocolAddr[1];
    unsigned char operationCode[2];
    uint8_t shAddr[6];
    unsigned char spAddr[4];
    unsigned char dhAddr[6];
    unsigned char dpAddr[4];
    
    int offset = 0;
    
    memcpy(hardwareType, (void *) packet, 2 * sizeof(uint8_t));
    offset += 2 * sizeof(uint8_t);
    
    memcpy(protocolType, (void *) packet + offset, 2 * sizeof(uint8_t));
    offset += 2 * sizeof(uint8_t);
    
    memcpy(&hardwareAddr, (void *) packet + offset, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    
    memcpy(&protocolAddr, (void *) packet + offset, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    
    memcpy(operationCode, (void *) packet + offset, 2 * sizeof(uint8_t));
    offset += 2 * sizeof(uint8_t);
    
    memcpy(shAddr, (void *) packet + offset, 6 * sizeof(uint8_t));
    offset += 6 * sizeof(uint8_t);
    
    memcpy(spAddr, (void *) packet + offset, 4 * sizeof(uint8_t));
    offset += 4 * sizeof(uint8_t);
    
    memcpy(dhAddr, (void *) packet + offset, 6 * sizeof(uint8_t));
    offset += 6 * sizeof(uint8_t);
    
    memcpy(dpAddr, (void *) packet + offset, 4 * sizeof(uint8_t));
    offset += 4 * sizeof(uint8_t);
    int16_t opCode = ntohs(*(int16_t*)operationCode);
    printf("opcode: %d\n", opCode);
    if (opCode == 1) {
        // The Message is a request, create reply
        offset = 0;
        memcpy(&buffer[offset], (void *)hardwareType, 2 * sizeof(uint8_t));
        offset += 2;
        memcpy(&buffer[offset], (void *)protocolType, 2 * sizeof(uint8_t));
        offset += 2;
        memcpy(&buffer[offset], (void *)hardwareAddr, sizeof(uint8_t));
        offset += 1;
        memcpy(&buffer[offset], (void *)protocolAddr, sizeof(uint8_t));
        offset += 1;
        add16BitToMsg(buffer, 2, offset);
        offset += 2;
        
        // TODO: find src hardware addr?
        memcpy(&buffer[offset], (void *)hwAddr, 6 * sizeof(uint8_t));
        offset += 6;

        memcpy(&buffer[offset], (void *)dpAddr, 4 * sizeof(uint8_t));
        offset += 4;
    
        memcpy(&buffer[offset], (void *)shAddr, 6 * sizeof(uint8_t));
        offset += 6;
        
        memcpy(&buffer[offset], (void *)spAddr, 4 * sizeof(uint8_t));
        offset += 4;
    } else { //ARP is reply
        
        uint32_t spAddrInt = ntohs(*(int32_t *) spAddr);
        cache = addARPEntry(cache, spAddrInt, shAddr);
    }
    printCache(cache);
    return opCode;
}

void createARPRequest(unsigned char * buffer, uint32_t gatewayIP, struct sr_if * interface){
    int offset = 0;
    add16BitToMsg(buffer, 1, offset);
    offset += 2;
    add16BitToMsg(buffer, 2048, offset);
    offset += 2;
    add8BitToMsg(buffer, 6, offset);
    offset += 1;
    add8BitToMsg(buffer, 4, offset);
    offset += 1;
    add16BitToMsg(buffer, 1, offset);
    offset += 2;
    
    //hwAddr of sending interface
    memcpy(&buffer[offset], (void *)interface->addr, 6 * sizeof(uint8_t));
    offset += 6;

    //ip of sending interface
    add32BitToMsg(buffer, interface->ip, offset);
    offset += 4;
    
    //memset to 0
    memset(&buffer[offset], 0, 6 * sizeof(uint8_t));
    offset += 6;
    
    //gatewayIp or Ip that we need the HwAddr for.
    add32BitToMsg(buffer, gatewayIP, offset);
}

void print_bytes(const void *object, size_t size)
{
    size_t i;
    
    printf("[ ");
    for(i = 0; i < size; i++)
    {
        printf("%02x ", ((const unsigned char *) object)[i]);
    }
    printf("]\n");
}

void add32BitToMsg(unsigned char* msg, uint32_t num, int index){
    //memset(&msg[index], '\0', sizeof(int32_t));
    uint32_t tsize = num;
    msg[index] = (tsize >> 24) & 0xFF;
    msg[index + 1] = (tsize >> 16) & 0xFF;
    msg[index + 2] = (tsize >> 8) & 0xFF;
    msg[index + 3] = tsize & 0xFF;
}
void add16BitToMsg(unsigned char *msg, uint16_t num, int index){
    //memset(msg[index], '\0', sizeof(int16_t));
    uint16_t tsize = num;
    msg[index] = (tsize >> 8) & 0xFF;
    msg[index + 1] = tsize & 0xFF;
}

void add8BitToMsg(unsigned char *msg, uint8_t num, int index){
    uint8_t tsize = num;
    msg[index] = tsize & 0xFF;
}

void printIntAsIP(uint32_t ipInt){
    struct in_addr addr;
    addr.s_addr = ipInt;
    printf("%s\n", inet_ntoa(addr));
}





/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
