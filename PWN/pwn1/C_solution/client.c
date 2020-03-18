#include "deps.h"


int old_main(int argc, char const *argv[]) 
{ 
    int sock = 0; 
    struct sockaddr_in addr; 
    char * buffer;
    char * package;
    int n;
    char * port;
    char * ipaddr;
    setAddrInfo(argc, argv, port, ipaddr, &addr);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    }
       
    int continue_flag = 1;
    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) ==  0){
        printf("Welcome to the Server!\n");
        while(continue_flag){
            printf("Type message to echo then hit enter, of 0 if you want to close the connection: ");
            myGetLine(&buffer, &n, stdin);
            printf("Sending message of %d bytes \n", n);
            send(sock , buffer, n , 0 ); 
            printf("Sent to server: %s ", buffer);
            printf("......\n");
            package = calloc(100, 1);
            package = read_message(5, sock, package);
            printf("Reply from Server: %s \n",package); 
            free(package);
            if((char) *buffer == '0'){
                continue_flag = 0;
            }
            free(buffer);
        }
    }
    return 0; 
} 

int main(int argc, char const *argv[]) 
{ 
    int sock = 0; 
    struct sockaddr_in addr; 
    char * buffer;
    char * package;
    int n;
    char * port;
    char * ipaddr;
    setAddrInfo(argc, argv, port, ipaddr, &addr);


    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    }
       
    int continue_flag = 1;
    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) ==  0){
        //Read prologue of connection
        package = calloc(1000, 1);
        char* addr_str = strtok(read_message(5, sock, package), "\n");
        long int libc_addr = strtol(addr_str, NULL, 0);
        printf("Addr: 0x%lx \n", libc_addr);
        free(package);
        /*
        myGetLine(&buffer, &n, stdin);
        printf("Sending message of %d bytes \n", n);
        send(sock , buffer, n , 0 ); 
        printf("Sent to server: %s ", buffer);
        printf("......\n");
        package = calloc(100, 1);
        package = read_message(5, sock, package);
        printf("Reply from Server: %s \n",package); 
        free(buffer);
        */
    }
    return 0; 
} 
