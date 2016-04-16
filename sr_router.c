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
    print_bytes(packet, len);
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
        //add32BitToMsg(replyMsg, iface->ip, offset);
        memcpy(&replyMsg[offset], (void *)iface->addr, 6 * sizeof(uint8_t));
        offset = offset + 6 *sizeof(uint8_t);
        memcpy(&replyMsg[offset], (void *) packet + offset, 2 * sizeof(uint8_t));
        offset = offset + 2 *sizeof(uint8_t);
        memcpy(&replyMsg[offset], replyARP, 28);
        print_bytes(replyMsg, 42);
        sr_send_packet(sr, replyMsg, 42, interface);
    }
    
    
    


    
    //unsigned char replyARP[sizeof(uint8_t) * len];
    //populateReplyARP(packet, )

    printf("*** -> Received packet of length %d \n",len);
    


}/* end sr_ForwardPacket */

void parseEthernetHeader(uint8_t * packet, unsigned char* dAddress, unsigned char* sAddress, uint16_t* type){
    int offset = 0;
    memcpy(dAddress, (void *)packet, 6 * sizeof(uint8_t));
    offset = offset + (sizeof(uint8_t) * 6);
    memcpy(sAddress, (void *)packet + offset, 6 * sizeof(uint8_t));
    offset = offset + (sizeof(uint8_t) * 6);
    char tempType[sizeof(uint8_t) * 2];
    memcpy(tempType, (void *)packet + offset, sizeof(uint8_t) * 2);
    *type = ntohs(*(int16_t *) tempType);
    //printf("Type: %d\n", *type);
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
    
//    print_bytes(packet, 28);
//    printf("Compare to:\n");

//    print_bytes(&hardwareType, 2);
//    print_bytes(&protocolType, 2);
//    print_bytes(&hardwareAddr, 1);
//    print_bytes(&protocolAddr, 1);
//    print_bytes(&operationCode, 2);
//    print_bytes(&shAddr, 6);
//    print_bytes(&spAddr, 4);
//    print_bytes(&dhAddr, 6);
//    print_bytes(&dpAddr, 4);
    
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





/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
