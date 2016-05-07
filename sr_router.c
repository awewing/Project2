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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

void parseEthernetHeader(uint8_t * packet, unsigned char* dAddress, unsigned char* sAddress, uint16_t* type);
void handleARPPacket(uint8_t * packet, unsigned char* hwAddr, unsigned char* buffer);
void print_bytes(const void *object, size_t size);
void add32BitToMsg(unsigned char *msg, int32_t num, int index);
void add16BitToMsg(unsigned char *msg, int16_t num, int index);
uint16_t cksumAlg(uint16_t *buf, int count);
uint8_t getIPHeaderLength(uint8_t * ipPacket);
void updateChkSum(uint8_t ipHL, uint8_t *ipHeader);
void add8BitToMsg(unsigned char *msg, int8_t num, int index);

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
        unsigned char replyARP[28];
        memset(replyARP, '\0', 28);
        handleARPPacket(packet + sizeof(char) * 14, iface->addr, replyARP);
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
    else if (type == 2048){//Type is IPv4
        int dropPacketFlag = 0;
        uint8_t * ipPacket = packet + sizeof(uint8_t) * 14;
        //Is IP destination the same as the router?
        int Bit32Size = sizeof(uint32_t);
        uint8_t ipDest[Bit32Size];
        memset(ipDest, 0, Bit32Size);
        memcpy(&ipDest[0], (void *) packet + sizeof(uint8_t) * 30, Bit32Size);
        uint32_t ipDestInt = *(uint32_t *)ipDest;
        print_bytes(ipDest, Bit32Size);
        printf("ifaceIP: %d\n",(iface->ip));
        printf("ipDest: %d\n",ipDestInt);
        //if (ipDest == iface->ip){
        //    dropPacketFlag = 1;
        //}
        //Check and decrement the TTL
        char ttlTemp[sizeof(uint8_t)];
        memcpy(ttlTemp, (void *)packet + sizeof(uint8_t) * 22, sizeof(uint8_t));
        //uint8_t ttl = ntohs(*(uint8_t *) ttlTemp);
        uint8_t ttl = *(uint8_t *) ttlTemp;
        printf("TTL: %d\n", ttl);
        ttl = ttl - 1;
        if (ttl < 1){
            dropPacketFlag = 1;
        }
        else{
            add8BitToMsg(packet, ttl, sizeof(uint8_t) * 22);
        }
        //update IP checksum field
        //Get IP header length
        uint8_t ipHL = getIPHeaderLength(ipPacket);
        printf("IPHL %d\n", ipHL);
        //End of IP header length

        //Checking that cksum algorithm works
        char ckTemp[sizeof(uint16_t)];
        memcpy(ckTemp, (void *) packet + sizeof(uint8_t) * 24, sizeof(uint16_t));
        uint16_t ckCompare = *(uint16_t *) ckTemp;
        printf("cksumSentIn: %d\n", ckCompare);
        updateChkSum(ipHL, ipPacket);
    }
    //Check ARP cache entries each time to see if they are over 15 seconds old.
    printf("*** -> Received packet of length %d \n",len);

}/* end sr_ForwardPacket */

void updateChkSum(uint8_t ipHL, uint8_t *ipHeader){
    uint16_t buf[ipHL * 2];
    uint8_t ipHL16Bit = ipHL * 2;
    memset(buf, 0, sizeof(uint16_t) * ipHL16Bit);
    memcpy(buf, (void *) ipHeader, sizeof(uint16_t) * ipHL16Bit);
    memset(&buf[5], 0, sizeof(uint16_t));
    print_bytes(buf, sizeof(uint16_t) * ipHL16Bit);
    uint16_t cksum = cksumAlg(buf, ipHL16Bit);
    add16BitToMsg(ipHeader, cksum, sizeof(uint8_t) * 10);
    print_bytes(ipHeader, sizeof(uint16_t) * ipHL16Bit);
    printf("calculatedChk: %d\n", cksum);
}

uint8_t getIPHeaderLength(uint8_t *ipPacket) {
    char ipHLTemp[sizeof(uint8_t)];
    memcpy(ipHLTemp, (void *) ipPacket, sizeof(uint8_t));
    print_bytes(ipHLTemp, sizeof(uint8_t));
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

void handleARPPacket(uint8_t * packet, unsigned char* hwAddr, unsigned char* buffer) {
    unsigned char hardwareType[2];
    unsigned char protocolType[2];
    unsigned char hardwareAddr[1];
    unsigned char protocolAddr[1];
    unsigned char operationCode[2];
    unsigned char shAddr[6];
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
    
    if (ntohs(*(int16_t *)operationCode) == 1) {
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
    }
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

void add32BitToMsg(unsigned char* msg, int32_t num, int index){
    //memset(&msg[index], '\0', sizeof(int32_t));
    int32_t tsize = num;
    msg[index] = (tsize >> 24) & 0xFF;
    msg[index + 1] = (tsize >> 16) & 0xFF;
    msg[index + 2] = (tsize >> 8) & 0xFF;
    msg[index + 3] = tsize & 0xFF;
}
void add16BitToMsg(unsigned char *msg, int16_t num, int index){
    //memset(msg[index], '\0', sizeof(int16_t));
    int16_t tsize = num;
    msg[index] = (tsize >> 8) & 0xFF;
    msg[index + 1] = tsize & 0xFF;
}

void add8BitToMsg(unsigned char *msg, int8_t num, int index){
    int8_t tsize = num;
    msg[index] = tsize & 0xFF;
}





/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
