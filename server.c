/*
** Group 50
** Chao-Chun Chan
** Adam Cassie
*/ 

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
#include "message.h"
#include <pthread.h>

// Constants defined here
#define USERS_MAX 3
#define LOGGED_IN_MAX 10
#define SESSION_MAX 5
#define SESSION_ID_MAX 50
#define CLIENTS_PER_SESSION_MAX 5
#define MAX_TIME 300.0

// Declare socket as global
int sockfd;

// Typedef's for structs below
typedef struct session session;
typedef struct client_cred client_cred;
typedef struct client_connection client_connection;

// Struct for each client's login credentials
struct client_cred {
    char client_id[MAX_NAME];
    char password[20];
};

// List of login credentials for allowed clients
client_cred creds_list[USERS_MAX];

// Struct for each session's details (ie. session ID and list of clients in this session)
struct session{
    char session_id[SESSION_ID_MAX];
    client_connection *joined_clients[CLIENTS_PER_SESSION_MAX];
};

// List of available sessions
session session_list[SESSION_MAX];

// Struct for each connected client
struct client_connection{
    char client_id[MAX_NAME];
    struct sockaddr_in remote_addr;
    double last_active;             // time when client connection was last active
    session* joined_sess;
};

// List of connected clients in the system
client_connection client_list[LOGGED_IN_MAX];

// Load database of credentials for allowed clients
void load_creds(){
    strcpy(creds_list[0].client_id,"admin");
    strcpy(creds_list[0].password,"adminpw");
    strcpy(creds_list[1].client_id,"user");
    strcpy(creds_list[1].password,"password");
    strcpy(creds_list[2].client_id,"elon");
    strcpy(creds_list[2].password,"musk");
    return;
}


// Check if login command by client is valid
bool auth_login(char* client_id, char* password, struct sockaddr_in *remote_addr ){
    
    for(int i=0;i<USERS_MAX;i++){

        // Check list of client credentials to authorize this login attempt
        if(strcmp(client_id, creds_list[i].client_id)==0 &&strcmp(password, creds_list[i].password)==0 ){
            
            // Successfully matched credentials in server database
            for(int j=0;j<LOGGED_IN_MAX;j++){
                if(strcmp(client_list[j].client_id,"")==0){
                    continue;
                }

                // Check if client already logged in
                if(strcmp(client_id, client_list[j].client_id)==0){
                    printf("User already logged in\n");
                    strcpy(password,"User already logged in");
                    return false;
                }
            }

            // Authorize login and update client list
            printf("Valid login\n");
            for(int k=0;k<LOGGED_IN_MAX;k++){
                if(strcmp(client_list[k].client_id,"")==0){
                    client_list[k].last_active = (double) clock();
                    strcpy(client_list[k].client_id,client_id);
                    memcpy(&(client_list[k].remote_addr), remote_addr, sizeof(struct sockaddr_in));
                    break;
                }
            }
            return true;
        }
    }

    // Failed to match any login credentials in server database
    printf("Invalid login %s %s\n",client_id,password);
    strcpy(password,"Invalid login");   // write reason for failed login to packet->data as required
    return false;
}


// Check if log out command by client is valid
bool log_out(char* client_id){
    for(int i=0;i<LOGGED_IN_MAX;i++){
        if(strcmp(client_list[i].client_id,"")==0){
            continue;
        }
        // Client logged in
        if(strcmp(client_id, client_list[i].client_id)==0){
            strcpy(client_list[i].client_id,"");
            return true;
        }
    }
    // Client not logged in
    printf("User is not logged in\n");
    return false;
}


// Check if create session command by client is valid
bool create_session(char* session_id, char* client_id){
    bool validate=false;

    // Check if client is logged in
    for(int i=0;i<LOGGED_IN_MAX;i++){
        if(strcmp(client_list[i].client_id,"")==0){
            continue;
        }
        // Client is logged in
        if(strcmp(client_id, client_list[i].client_id)==0){
            validate=true;
            break;
        }
    }
    // Client not logged in
    if(!validate){  
        printf("Unregistered user tried to create session\n");
        return false;
    }
    // Check if session already exists
    validate=false;
    for(int i=0;i<SESSION_MAX;i++){
        if(strcmp(session_list[i].session_id,"")==0){
            continue;
        }
        if(strcmp(session_id, session_list[i].session_id)==0){
            validate=true;
            break;
        }
    }
    // Session already exists
    if(validate){
        printf("Requested session id already exists\n");
        return false;
    }
    // Check if max number of sessions is reached yet
    for(int i=0;i<SESSION_MAX;i++){
        if(strcmp(session_list[i].session_id,"")==0){
            strcpy(session_list[i].session_id,session_id);
            return true;
        }
    }
    printf("Max number of sessions reached\n");
    return false;
}


// Check if join command by user is valid
bool join_session(char* session_id,char* client_id){
    //session_id is the same location as the packet_data

    // Check if session exists, then add this client to the session
    for(int i=0;i<LOGGED_IN_MAX;i++){
        if(strcmp(client_list[i].client_id,"")==0){
            continue;
        }
        if(strcmp(client_id, client_list[i].client_id)==0){
            for(int j=0;j<SESSION_MAX;j++){
                if(strcmp(session_list[j].session_id,"")==0){
                    continue;
                }
                // Session exists
                if(strcmp(session_list[j].session_id,session_id)==0){
                    client_list[i].joined_sess=&session_list[j];
                    for(int k=0;k<CLIENTS_PER_SESSION_MAX;k++){
                        if(session_list[j].joined_clients[k]==NULL){
                            session_list[j].joined_clients[k]=&client_list[i];
                            return true;
                        }
                    }
                    strcpy(session_id,"The requested session has reached max client size");
                    return false;
                }
            }
            // Session does not exist
            strcpy(session_id,"The requested session does not exist");
            return false;
        }
    }
    // Client not logged in
    strcpy(session_id,"This user is not logged in");
    return false;
}

// Check if invite command by user is valid
bool invite_session(char* args,char* sender_id){
    struct sockaddr_in receiver_addr;

    // Get the client ID for the invite recipient and the session id
    char* strtok_temp;
    char receiver_id[100];
    char session_id[100];
    strtok_temp = strtok(args," \n" );
    if(strtok_temp == NULL) {
        printf("Insufficient arguments to send invite\n");
        return false;
    }
    strcpy(receiver_id, strtok_temp);
    strtok_temp = strtok(NULL," \n" );
    if(strtok_temp == NULL) {
        printf("Insufficient arguments to send invite\n");
        return false;
    }
    strcpy(session_id, strtok_temp);

    // Check if the session exists
    int i;  // index into session_list (gives the requested session after the loop)
    bool session_exists = false;
    for(i = 0; i < SESSION_MAX; ++i) {
        if(strcmp(session_list[i].session_id, session_id) == 0) {
            session_exists = true;
            break;
        }
    }
    if(!session_exists) {
        printf("The requested session does not exist\n");
        return false;
    }

    // Check if the sender and receiver exist and whether they are in the session (with index i)
    bool valid_sender = false;
    bool valid_receiver = false;
    for(int j = 0; j < LOGGED_IN_MAX; ++j) {
        if(strcmp(client_list[j].client_id, "") == 0){
            continue;
        }
        else if(strcmp(client_list[j].client_id, sender_id)==0){   
            for(int k = 0; k < CLIENTS_PER_SESSION_MAX; ++k) {
                if(session_list[i].joined_clients[k]->client_id == NULL) {
                    continue;
                }
                if(strcmp(sender_id, session_list[i].joined_clients[k]->client_id) == 0) {
                    valid_sender = true;
                    break;
                }  
            }
        }
        else if(strcmp(client_list[j].client_id, receiver_id)==0){
            receiver_addr = client_list[j].remote_addr;
            valid_receiver = true;
            for(int k = 0; k < CLIENTS_PER_SESSION_MAX; ++k) {
                if(session_list[i].joined_clients[k]->client_id == NULL) {
                    continue;
                }
                if(strcmp(receiver_id, session_list[i].joined_clients[k]->client_id) == 0) {
                    valid_receiver = false;
                    break;
                }
            }
        }
    }
    if(!valid_sender) {
        printf("The invitation sender is not in the requested session\n");
        // printf("\nSender problem\n");
        return false;
    }
    if(!valid_receiver) {
        printf("The invited client is either not logged in or already in the session\n");
        // printf("\nReceiver problem\n");
        return false;
    }

    // Relay the invite to the receiver
    char buffer[BUF_SIZE];
    packet *pkt= (packet *)malloc(sizeof(packet));
    pkt->type = RELAY;
    strcpy(pkt->source, sender_id); // packet source is the original sender
    strcpy(pkt->data, session_id);  // packet data is the session id
    pkt->size=strlen(pkt->data);
    memset(buffer,0,BUF_SIZE);
    ptos(pkt,buffer);
    free(pkt);
    if(sendto(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr)) == -1){
        printf("Failed to relay invitation to receiver client\n");
        return false;
    }
    printf("Successfully relayed invitation\n");
    return true;
}


// Check if leave command by client is valid
bool leave_session(char* client_id){
    session *client_sess;
    // Check if client is logged in
    for(int i=0;i<LOGGED_IN_MAX;i++){
        if(strcmp(client_list[i].client_id,"")==0){
            continue;
        }
        if(strcmp(client_id, client_list[i].client_id)==0){

            // Check if client is actually in any session
            if(client_list[i].joined_sess == NULL) {
                printf("Client is not part of any session\n");
                return false;
            }

            client_sess=client_list[i].joined_sess;
            client_list[i].joined_sess=NULL;
            for(int j=0;j<CLIENTS_PER_SESSION_MAX;j++){
                if(client_sess->joined_clients[j]==NULL){
                    continue;
                }
                if(client_sess->joined_clients[j]==&client_list[i]){
                    client_sess->joined_clients[j]=NULL;
                    break;
                }
            }
            for(int k=0;k<SESSION_MAX;k++){
                if(client_sess->joined_clients[k]!=NULL){
                    return true;
                }
            }
            strcpy(client_sess->session_id,"");
            return true;
        }
    }
    printf("Error, Client tried to leave session without joining one\n");
    return false;
}

// Returns number of clients to forward the text to (not including self)
// Also saves a list of client_connections that need to be sent the text
int receive_text(char* data, char* client_id, client_connection* send_list[CLIENTS_PER_SESSION_MAX]){
    int num_clients=0;
    session *session_info;

    for(int i=0;i<LOGGED_IN_MAX;i++){
        //find the client that sent the text
        if(strcmp(client_list[i].client_id,"")==0){
            continue;
        }
        // Get session to which this client belongs
        if(strcmp(client_id,client_list[i].client_id)==0){//found 
            session_info=client_list[i].joined_sess;
        }
    }

    // Check if client belonged to any session
    if(session_info == NULL) {
        printf("Client does not belong to a session. Ignoring message.\n");
        return 0;
    }

    for(int j=0;j<CLIENTS_PER_SESSION_MAX;j++){
        //count number of clients in session and add to send_list
        if(session_info->joined_clients[j]!=NULL){
            
            if(strcmp(session_info->joined_clients[j]->client_id,client_id)!=0){
                //if not sender
                send_list[num_clients]=session_info->joined_clients[j];
                num_clients++;
            }
        }
    }
    return num_clients;
}


// Get list of online users and available sessions
void query(char* data){
    memset(data,0,MAX_DATA);
    strcpy(data,"");

    // Get list of clients
    strcat(data,"\nCLIENTS\n");
    for(int i=0;i<LOGGED_IN_MAX;i++){
        if(strcmp(client_list[i].client_id,"")==0){
            continue;
        }
        else{
            strcat(data,client_list[i].client_id);
            strcat(data,"\n");
        }
    }

    // Get list of sessions
    strcat(data,"\nSESSIONS\n");
    for(int i=0;i<SESSION_MAX;i++){
        if(strcmp(session_list[i].session_id,"")==0){
            continue;
        }
        else{
            strcat(data,session_list[i].session_id);
            strcat(data,"\n");
        }
    }
    return;
}


// Check timer for each client and send timeout for any inactive client
void* timer_func( void *sockfd_p){
    
    // Declare variables for sending timeout directives to client
    char buffer [BUF_SIZE];
    int *sockfd=(int *)sockfd_p;
    // struct sockaddr_in remote_addr;
    packet* pkt=(packet*)malloc(sizeof(packet));
    
    while(true){
        for(int i = 0; i < LOGGED_IN_MAX; ++i) {
            if(strcmp(client_list[i].client_id,"")==0){
                continue;
            }
            else {  // Check when the client was last active
                if (((double)(clock()-client_list[i].last_active))/CLOCKS_PER_SEC > MAX_TIME) {
                    pkt->type = TIMEOUT;
                    pkt->size = 0;
                    strcpy(pkt->source, client_list[i].client_id);
                    strcpy(pkt->data, "Timeout due to inactivity. Logged out of server");
                    ptos(pkt, buffer);
                    if((sendto(*sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&(client_list[i].remote_addr),sizeof(client_list[i].remote_addr)) ) == -1){
                        printf("Failed to send timeout to Client: %s\n", client_list[i].client_id);
                    }
                    else {
                        printf("Kicking Client: %s from server due to inactivity\n", client_list[i].client_id);
                        leave_session(client_list[i].client_id);
                        log_out(client_list[i].client_id);
                    }
                }
            }
        }    
    }
}

// Update the time at which a client was last active
bool update_client_clock(char *client_id) {
    for(int i = 0; i < LOGGED_IN_MAX; ++i) {
        if(strcmp(client_list[i].client_id,"")==0){
            continue;
        }
        else if(strcmp(client_list[i].client_id, client_id)==0) {
            client_list[i].last_active = (double) clock();
            return true;
        }
    }
    return false;
}

int main (int argc, char const *argv[]){
    // Check if port number is included
    if (argc < 2) {
        printf("Insufficient arguments. Try again with port number\n");
        return 0;
    }

    int port_num = atoi(argv[1]);   // Server port number from command line

    // Start socket
    sockfd= socket(PF_INET, SOCK_DGRAM,0);
    if(sockfd == -1){
        //report error
        return 0;
    } 
    struct sockaddr_in addr;
    memset(addr.sin_zero,0,sizeof(addr.sin_zero));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr= htonl(INADDR_ANY);
    addr.sin_port=htons(port_num);
    if(bind(sockfd,(struct sockaddr*) &addr,sizeof(addr)) == -1){
        //report error
        return 0;
    }
    
    // Load database of credentials for allowed clients
    load_creds();

    // Declare variables to listen for client message
    unsigned char buffer[BUF_SIZE];
    int recv_length;
    struct sockaddr_in remote_addr;
    int remote_len;

    // Set up thread to handle client timeouts
    pthread_t timer_thread;
    if(pthread_create(&timer_thread, NULL, (void*)timer_func, (void*)&sockfd) == 0){
        // printf("Inactivity timer feature is activated\n");
    }

    // Start listening for client message
    while(true){

        printf("Waiting on port %d\n", port_num);
        memset(buffer,0,BUF_SIZE);

        // Receive message from client
        remote_len=sizeof(remote_addr);
        recv_length = recvfrom(sockfd, buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr, &remote_len);
        if(recv_length == -1 ){
            printf("Failed to receive message\n");
            return 0;
        }

        // Convert string format message to packet format
        packet *pkt=(packet*)malloc(sizeof(packet));
        memset(pkt->source,0,MAX_NAME);
        memset(pkt->data,0,MAX_DATA);
        pkt->size=0;
        pkt->type=0;
        stop(buffer, pkt);
        //memset(buffer,0,BUF_SIZE);

        // Process client message based on type
        if(pkt->type==LOGIN){       // Client message is a login
            if(auth_login(pkt->source, pkt->data,&remote_addr)){
                pkt->type=LO_ACK;   // login successful
            }
            else{
                pkt->type=LO_NAK;   // login unsuccessful
            }
            pkt->size=strlen(pkt->data);
            memset(buffer,0,BUF_SIZE);
            ptos(pkt,buffer);       // convert server response to string format to send to client
            if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                printf("Failed to send response\n");
            }
        }

        else if(pkt->type==EXIT){       // Client message is an exit
            leave_session(pkt->source); // Leave session before exiting 
            if(log_out(pkt->source)){
                printf("Logout successful\n");
            }
            else {
                printf("Logout unsuccessful\n");
            }
        }

        else if(pkt->type==JOIN){   // Client message is a join
            if(join_session(pkt->data,pkt->source)){
                memset(buffer,0,BUF_SIZE);
                pkt->type=JN_ACK;   // successful join
                //data unchanged
                ptos(pkt,buffer);   // convert server response to string format
                if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                    printf("Failed to send response\n");
                }
                printf("User joined session\n");
            }
            else{
                memset(buffer,0,BUF_SIZE);
                pkt->type=JN_NAK;   // join unsuccessful
                pkt->size=strlen(pkt->data);
                ptos(pkt,buffer);   // convert server response to string format
                if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                    printf("Failed to send response\n");
                }
                printf("User failed to join session\n");
            }
        }

        else if(pkt->type==LEAVE_SESS){ // Client message is a leave
            if(leave_session(pkt->source)){
                printf("Left session successfully\n");
            }
            else{
                printf("Failed to leave session\n");
            }
        }

        else if(pkt->type==NEW_SESS){   // Client message is a create session
            if(create_session(pkt->data,pkt->source)){
                memset(buffer,0,BUF_SIZE);
                pkt->type=NS_ACK;
                //data unchanged
                ptos(pkt,buffer);       // convert server response to string format

                if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                    printf("Failed to send response\n");
                }
                printf("New session created\n");
            }
            else{
                printf("New session error\n");
            }
        }

        else if(pkt->type==QUERY){      // Client message is a query
            query(pkt->data);
            memset(buffer,0,BUF_SIZE);
            pkt->type=QU_ACK;
            pkt->size=strlen(pkt->data);
            ptos(pkt,buffer);           // Convert server response to string format
            // printf("Sending %s",buffer);
            if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                printf("Failed to send response\n");
            }
            printf("Query successful\n");
            
        }

        else if(pkt->type==MESSAGE){    // Client message is a text
            client_connection * send_list[CLIENTS_PER_SESSION_MAX];
            int send_num=receive_text(pkt->data,pkt->source,send_list);

            if(send_num!=0){         
                ptos(pkt,buffer);           // convert server response to string format
                for(int j=0;j<send_num;j++){
                    remote_addr=send_list[j]->remote_addr;
                    if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                        printf("Failed to send response\n");
                    }
                }
            }
        }

        else if(pkt->type==INVITE){   // Client message is an invite
            if(invite_session(pkt->data,pkt->source)){
                // Acknowledge to the sender that the invite has been relayed
                memset(buffer,0,BUF_SIZE);
                pkt->type=INV_ACK;   // successful invite
                //data unchanged
                ptos(pkt,buffer);   // convert server response to string format
                if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                    printf("Failed to send ACK for invite\n");
                }
                printf("Sent ACK for invite\n");
            }
            else{
                memset(buffer,0,BUF_SIZE);
                pkt->type=INV_NAK;  // join unsuccessful
                pkt->size=strlen(pkt->data);
                ptos(pkt,buffer);   // convert server response to string format
                if((sendto(sockfd,buffer, BUF_SIZE,0,(struct sockaddr*)&remote_addr,sizeof(addr)) ) == -1){
                    printf("Failed to send NACK for invite\n");
                }
                printf("Sent NACK for invite\n");
            }
        }

        else if(pkt->type==RSVP){   // Client message is an rsvp for a precious invitation
            char* strtok_temp;
            char decision[100];
            char session_id[100];
            strtok_temp = strtok(pkt->data," \n" );
            strcpy(decision, strtok_temp);
            strtok_temp = strtok(NULL," \n" );
            strcpy(session_id, strtok_temp);
            
            if(strcmp(decision, "accept") == 0) {
                printf("Invitation was accepted by client\n");
                leave_session(pkt->source);
                join_session(session_id, pkt->source);
            }
            else {
                printf("Invitation was rejected by client\n");
            }
        }

        else{
            //unknown message type
            printf("Unknown message type received\n");
        }

        // Update the time at which this client was last active
        if (update_client_clock(pkt->source) == false) {
            printf("Error in updating last active time for Client: %s\n", pkt->source);
        }

        free(pkt);
    }
}