#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "message.h"
#include <pthread.h>

// Define constants
#define MAX_ATTEMPTS 10

// Declare global character buffers
char buffer [BUF_SIZE];
char text_message [BUF_SIZE];
char my_id[100];
char invited_session[100];                      // stores session id for session client is invited to

// Declare global flags to control client state
bool quit = false;                              // flag to indicate if client entered quit command
bool logged_in = false;                         // flag to indicate if this client is logged in
bool timeout = false;
bool pending_invitation = false;

// Declare global variables for setting up client-server connection
int sockfd;
struct addrinfo *servinfo;

enum COMMANDS{      // Commands to be implemented for client (see instructions)
    LOGIN_COM,
    LOGOUT,
    JOIN_COM,
    LEAVE,
    CREATE,
    LIST,
    QUIT,
    INVITE_COM,
    ACCEPT,
    REJECT,
    TEXT
};

// Get client command from stdin file stream and return command type
int get_command(char* buf){
    char *strtok_temp;
    char command[14];           // just enough space
    fgets(buf, BUF_SIZE,stdin); // get command string from stdin
    strcpy(text_message, buf);  // for purpose of printing text message
    strtok_temp = strtok(buffer," \n");
    strcpy(command,strtok_temp);
    
    // Logic to return command type
    if(strcmp(command, "/login")==0){
        return LOGIN_COM;
    }
    else if(strcmp(command, "/logout")==0){
        return LOGOUT;
    }
    else if(strcmp(command, "/joinsession")==0){
        return JOIN_COM;
    }
    else if(strcmp(command, "/leavesession")==0){
        return LEAVE;
    }
    else if(strcmp(command, "/createsession")==0){
        return CREATE;
    }
    else if(strcmp(command, "/list")==0){
        return LIST;
    }
    else if(strcmp(command, "/quit")==0){
        return QUIT;
    }
    else if(strcmp(command, "/invite")==0){
        return INVITE_COM;
    }
    else if(strcmp(command, "/accept")==0){
        return ACCEPT;
    }
    else if(strcmp(command, "/reject")==0){
        return REJECT;
    }
    else{   //assume is text will have to check state 
        return TEXT;
    }
}

// Get and process server responses to this client
void* receive_func( void *sockfd_p){
    
    // Declare variables for receiving server responses for this client
    char buffer_recv [BUF_SIZE];
    int *sockfd_recv=(int *)sockfd_p;
    packet* pkt=(packet*)malloc(sizeof(packet));
    struct sockaddr_in server_addr;
    int server_len=sizeof(server_addr);
    
    while(true){
        // Get response from server
        int recvlen= recvfrom(*sockfd_recv, buffer_recv, BUF_SIZE, 0, (struct sockaddr*)&server_addr, &server_len);
        if(recvlen == -1 ){
            printf("Failed to receive response from server\n");
        }
        stop(buffer_recv,pkt);      // convert string format to packet format
        
        // Process server response (based on type)
        if(pkt->type == JN_ACK){
            printf("Successfully joined conference session\n");
        }
        else if (pkt->type == JN_NAK) {
            printf("Failed to join conference session\n");
            printf("reason: %s\n",pkt->data);
        } 
        else if(pkt->type == NS_ACK) {
            printf("Successfully created conference session\n");
        }
        else if(pkt->type == QU_ACK) {
            printf("%s\n", pkt->data);
        }
        else if(pkt->type == MESSAGE) {
            printf("%s: %s\n",pkt->source,pkt->data);
        }
        else if(pkt->type == TIMEOUT) {
            printf("\nTIMEOUT. Type 'ok' to continue\n");
            // printf("%s\n",pkt->data);
            logged_in = false;
            timeout = true;
            freeaddrinfo(servinfo);
            close(sockfd);
            return (void*) 0;
        }
        else if(pkt->type == INV_ACK) {
            printf("Invitation successfully relayed\n");
        }
        else if(pkt->type == INV_NAK) {
            printf("Failed to relay invitation\n");
        }
        else if(pkt->type == RELAY) {
            strcpy(invited_session, pkt->data);
            pending_invitation = true;
            printf("Received invitation from Client: %s for Session: %s\n", pkt->source, pkt->data);
            printf("Type 'ok' to continue\n");
        }
        else{
            printf("Unexpected response from server\n");
        }
    }
}

// Wait for the client to login before doing anything else
bool wait_for_login(int *sockfd, struct addrinfo **servinfo, pthread_t *receive_thread) {
    // Declare variables for getting input from client
    int command_type;
    char client_id[100];
    char password[20];
    char server_ip[17];
    char server_port[6];
    packet *pkt= (packet *)malloc(sizeof(packet));  // packet structure to send command message to server
    
    // Declare variables for setting up client-server connection
    int recvlen;
    struct sockaddr_in server_addr;
    int server_len=sizeof(server_addr);
    char *strtok_temp;
    int status;
    struct addrinfo hints;
    
    // Get client login details first
    while(true){

        // Get the first command from client
        command_type= get_command(buffer);  
        if(command_type!=LOGIN_COM){        // First command must be a login
            printf("Login first\n");        // Try again until login
            continue;
        }
        
        // Get the remaining data for client login command
        strtok_temp = strtok(NULL," " );    // get client ID
        if(strtok_temp == NULL) {
            printf("Insufficient arguments for login. Try again\n");
            continue;
        }
        strcpy(client_id,strtok_temp);
        strcpy(my_id, client_id);           // store client id in global for use in main
        
        strtok_temp = strtok(NULL," " );    // get password
        if(strtok_temp == NULL) {
            printf("Insufficient arguments for login. Try again\n");
            continue;
        }
        strcpy(password,strtok_temp);
        
        strtok_temp = strtok(NULL," " );    // get server IP
        if(strtok_temp == NULL) {
            printf("Insufficient arguments for login. Try again\n");
            continue;
        }
        strcpy(server_ip,strtok_temp);   

        strtok_temp = strtok(NULL," \n" );   // get server port number
        if(strtok_temp == NULL) {
            printf("Insufficient arguments for login. Try again\n");
            continue;
        }
        strcpy(server_port,strtok_temp);

        // Set up the packet with the login command to send to the server
        pkt->type=LOGIN;
        pkt->size=strlen(password);
        strncpy(pkt->source, client_id,MAX_NAME);
        strncpy(pkt->data,password, MAX_DATA);
        memset(buffer,0,BUF_SIZE);
        ptos(pkt,buffer);   // Convert to packet format to string format for sending

        // Set up client-server connection (use server port and IP passed in by client on login)
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;
        if((status=getaddrinfo(server_ip,server_port,&hints,servinfo )) == -1){
            printf("getaddrinfo error\n");
            exit(0);
        }      
        if((*sockfd= socket((*servinfo)->ai_family, (*servinfo)->ai_socktype,(*servinfo)->ai_protocol)) == -1 ){
            printf("socket error\n");
            freeaddrinfo(*servinfo);
            exit(0);
        }    

        //error checking here -TODO

        // Send login data to server
        if(sendto(*sockfd, buffer, BUF_SIZE, 0, (*servinfo)->ai_addr, (*servinfo)->ai_addrlen) == -1){
            fprintf(stderr, "Error sending login data to server\n");
            exit(1);
        }

        // Get server response for login data
        recvlen= recvfrom(*sockfd, buffer, BUF_SIZE, 0, (struct sockaddr*)&server_addr, &server_len);
        if(recvlen == -1 ){
            printf("Failed to receive response from server\n");
        }
        else{
            stop(buffer,pkt);       // Convert server response to packet format
            if(pkt->type==LO_ACK){  // Successful login, so start receive thread subsequent server responses
                if(pthread_create(receive_thread, NULL, (void*)receive_func, (void*)sockfd) == 0){
                    printf("Login successful\n");
                    if(timeout) {   // reset timeout flag if this caused logout
                        timeout = false;
                    }
                    free(pkt);
                    return true;
                }
            }
            else if (pkt->type==LO_NAK){//TODO- Unavailble socket/port number
                printf("Login unsuccessful try again\n");
                printf("reason: %s\n",pkt->data);
            } 
            else{
                printf("Unknown data type\n");
            }
        }
    }
}

// Wait for client to accept or reject it's pending invitation
bool wait_for_rsvp(int *sockfd, struct addrinfo **servinfo) {
    
    // Declare variables for getting input from client
    int command_type;
    packet *pkt= (packet *)malloc(sizeof(packet));

    while(true) {

        // Wait for an accept or reject command from client
        command_type= get_command(buffer);  
        if(command_type != ACCEPT && command_type != REJECT) {            // First command must be a login
            printf("Accept or Reject pending invitation to continue\n");  // Try again until login
            continue;
        }

        pkt->type = RSVP;
        strcpy(pkt->source, my_id);

        if(command_type == ACCEPT) {
            strcpy(pkt->data, "accept");
                  
        }
        else if(command_type == REJECT) {
            strcpy(pkt->data, "reject");
        }
        strcat(pkt->data, " ");
        strcat(pkt->data, invited_session);
        pkt->size=strlen(pkt->data);    
        ptos(pkt,buffer);
        if(sendto(*sockfd, buffer, BUF_SIZE, 0, (*servinfo)->ai_addr, (*servinfo)->ai_addrlen) == -1){
            printf("Invitation still longer pending\n");
        }
        else {
            return false;
        }
    }
}

int main (int argc, char const *argv[]){

    // Declare variables for getting input from client and server
    char *strtok_temp;
    packet *pkt= (packet *)malloc(sizeof(packet));  // packet structure to send command message to server
    pthread_t receive_thread;

    // Loop to handle subsequent commands from client after login
    while (true) {
        // Check if currently logged in
        if (!logged_in) {
            logged_in = wait_for_login(&sockfd, &servinfo, &receive_thread);
            continue;
        }

        if (pending_invitation) {
            printf("Now waiting for RSVP\n");
            pending_invitation = wait_for_rsvp(&sockfd, &servinfo);
            continue;
        }

        memset(buffer,0,BUF_SIZE);                  // clear buffer to get next command
        int command_type= get_command(buffer);
        strcpy(pkt->source, my_id);             // set message source
        
        // Set message type, data and size based on command type
        if (command_type == QUIT || command_type == LOGOUT) {
            if (command_type == QUIT) {
                quit = true;
            }
            pkt->type = EXIT;
            pkt->size = 0;
            strcpy(my_id, "");      // clear current client ID
            logged_in = false;
        }
        else if (command_type == LEAVE) {
            pkt->type = LEAVE_SESS;
            pkt->size = 0;
        }
        else if(command_type == LIST) {
            pkt->type = QUERY;
            pkt->size = 0;
        }
        else if (command_type == JOIN_COM) {
            pkt->type = JOIN;
            char session_id[100];
            strtok_temp = strtok(NULL," \n" );
            if(strtok_temp == NULL) {
                printf("Insufficient arguments to create a session. Try again\n");
                continue;
            }
            strcpy(session_id,strtok_temp);
            strncpy(pkt->data, session_id, MAX_DATA);
            pkt->size = sizeof(session_id);
        }
        else if (command_type == CREATE) {
            pkt->type = NEW_SESS;
            char session_id[100];
            strtok_temp = strtok(NULL," \n" );
            if(strtok_temp == NULL) {
                printf("Insufficient arguments to create a session. Try again\n");
                continue;
            }
            strcpy(session_id,strtok_temp);
            strncpy(pkt->data, session_id, MAX_DATA);
            pkt->size = sizeof(session_id);
        }
        else if (command_type == INVITE_COM) {
            pkt->type = INVITE;
            char invite_args[100];
            strtok_temp = strtok(NULL," \n" );
            if(strtok_temp == NULL) {
                printf("Insufficient arguments to create a session. Try again\n");
                continue;
            }
            strcpy(invite_args,strtok_temp);
            strtok_temp = strtok(NULL," \n" );
            if(strtok_temp == NULL) {
                printf("Insufficient arguments to create a session. Try again\n");
                continue;
            }
            strcat(invite_args, " ");
            strcat(invite_args, strtok_temp);
            strncpy(pkt->data, invite_args, MAX_DATA);
            pkt->size = sizeof(invite_args);
        }
        else if (command_type == TEXT) {
            pkt->type = MESSAGE;
            strcpy(pkt->data, text_message);
            pkt->size=strlen(pkt->data);
        }
        else {
            // should not enter this case
            printf("Invalid command entered. Try again.\n");
            continue;
        }

        // Send message based on client command to the server
        memset(buffer,0,BUF_SIZE);
        ptos(pkt,buffer);                           // convert packet format to string format
        if(sendto(sockfd, buffer, BUF_SIZE, 0, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
            printf("Ensure that you are logged in\n");
            continue;
        }

        // Terminate client program if quit flag raised
        if(quit) {
            printf("Terminating client program\n");
            break;
        }

        // Close connection if logout command was performed
        if(!logged_in && !timeout) {
            freeaddrinfo(servinfo);
            close(sockfd);
        }
    }

    free(pkt);
    freeaddrinfo(servinfo);
    close(sockfd);

    return 0;
}
