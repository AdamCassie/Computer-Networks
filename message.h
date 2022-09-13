#ifndef MESSAGE_H
#define MESSAGE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_NAME 128
#define MAX_DATA 2048
#define BUF_SIZE 2048 


enum types{     // types for the control messages (see instructions)
    LOGIN,
    LO_ACK,
    LO_NAK,
    EXIT,
    JOIN,
    JN_ACK,
    JN_NAK,
    LEAVE_SESS,
    NEW_SESS,
    NS_ACK,
    MESSAGE,
    QUERY,
    QU_ACK,
    INVITE,
    INV_ACK,
    INV_NAK,
    RELAY,
    RSVP,
    TIMEOUT
};


struct message {                    // structure for data and control messages
    unsigned int type;              // type of the message
    unsigned int size;              // length of the data being sent
    unsigned char source[MAX_NAME]; // contains the ID of the client sending the message
    unsigned char data[MAX_DATA];   // data being sent
};
typedef struct message packet;      // this is the packet format for a message


// Convert message from string format to packet format
void stop (char* string, packet* pkt){
    memset(pkt,0,sizeof(packet));

    char *strtok_temp;
    //message type
    strtok_temp = strtok(string,": ");
    pkt->type = atoi(strtok_temp);

    //message size
    strtok_temp = strtok(NULL,":" );
    pkt->size = atoi(strtok_temp);

    //source
    strtok_temp = strtok(NULL,":" );
    strcpy(pkt->source,strtok_temp);

    //data
    strtok_temp = strtok(NULL,":" );
    memcpy(pkt->data,strtok_temp,pkt->size);

    //printf("data = %s\n",pkt->filedata);
}


// Convert message from packet format to string format
void ptos(const packet* pkt, char* string) {

    char temp [4];
    memset(string, 0, BUF_SIZE);        // string initialized
    sprintf(temp, "%d",pkt->type);
    strcat(string, temp);
    strcat(string, ":");
    sprintf(temp, "%d",pkt->size);
    strcat(string, temp);
    strcat(string, ":");
    strcat(string, pkt->source);
    strcat(string, ":");
    strcat(string, pkt->data);

}

#endif