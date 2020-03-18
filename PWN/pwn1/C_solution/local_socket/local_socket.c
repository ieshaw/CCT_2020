#include "local_socket.h"

int SocketDemoUtils_createTcpSocket(){
    int sockFd = 0;
    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    //check for error
    if(sockFd == -1){
        perror("socket");
    }
    int opt = 1; 
    if( -1 == setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                          &opt, sizeof(opt))){
        sockFd = -1 ;
    }
    return sockFd;
}

int SocketDemoUtils_populateAddreInfo(char *port, char *ipAddr, struct sockaddr_in *addr){
    addr->sin_family = AF_INET;
    short int port_num = (short) strtol(port, NULL, 10);
    if((port_num > 1023) && (49151 > port_num)){ 
        addr->sin_port = htons((short) strtol(port, NULL, 10)); 
        return inet_aton(ipAddr, &(addr->sin_addr));
    } else {
        return 0;
    }
}

int SocketDemoUtils_bind(int sockFd, struct sockaddr_in *addr){
    return bind(sockFd, (struct sockaddr *)addr, sizeof(*addr));
}

int SocketDemoUtils_listen(int sockFd){
    return listen(sockFd, 3);
}

int SocketDemoUtils_accept(int sockFd, struct sockaddr_in *addr){
    socklen_t addrlen = (socklen_t) sizeof(addr);
    return accept(sockFd, (struct sockaddr *) addr, &addrlen);
}

int SocketDemoUtils_recv(int sockFd, char *buf, int chunk, int waitFlag){
    if( waitFlag){
        return recv(sockFd, buf, chunk, 0);
    } else {
        return recv(sockFd, buf, chunk, MSG_DONTWAIT);
    }
}

int SocketDemoUtils_send(int sockFd, char *buf, int numBytes){
    return send(sockFd, buf, numBytes, 0);
}

int myGetLine(char ** lineptr, int * n, FILE *stream){
    *lineptr = calloc(2, 1);
    char * tracker = *lineptr;
    *n = 0;
    char i = getc(stream);
    while((i != '\0') && (i !='\n') && (i != EOF)){
        memcpy(tracker, &i, 1);
        *n += 1;
        tracker = realloc(*lineptr, ((*n) + 2));
        if(tracker){
            *lineptr = tracker;
        } else {
            perror("Realloc failed in myGetLine. \n");
        }
        tracker = *lineptr + *n;
        memset(tracker, 0, 1); 
        i = getc(stream);
    }
    memcpy(tracker, "\n\0", 1);
    *n++;
    return 1;
}

char *read_message(int chunk, int clientFd, char* buf){
    int n_chunks = 0;
    int bytesReceived;
    char * scratch;
    scratch = calloc(chunk, 1);
    if(!scratch){
        perror("Calloc failed in read message.\n");
    }
    buf = scratch;
    bytesReceived = SocketDemoUtils_recv(clientFd, (buf+ (chunk * n_chunks)), chunk, 1);
    if(bytesReceived < 0){
        perror("recv failed.");
    }
    //printf("Receiving message from socket %d. %d bytes received. Chunk #%d \n", clientFd, bytesReceived, n_chunks);
    while( (bytesReceived == chunk) && (n_chunks * chunk < 1000))
        {
        n_chunks += 1;
        scratch = realloc(buf, (n_chunks +1)*chunk);
        if(!scratch){
            perror("Realloc failed in read message.\n");
        }
        buf = scratch;
        bytesReceived = SocketDemoUtils_recv(clientFd, (buf+ (chunk * n_chunks)), chunk, 0);
        //printf("Receiving message from socket %d. %d bytes received. Chunk #%d \n", clientFd, bytesReceived, n_chunks);
        }
    return buf;
}

void setAddrInfo(int argc, char const *argv[], char * port, char * ipaddr, struct sockaddr_in *addr){
    int valid_IP = 0;
    if(argc == 3){
        ipaddr = argv[1];
        port = argv[2];
        if(!(SocketDemoUtils_populateAddreInfo(port, ipaddr, addr))){
                printf("Invalid IP address or port \n");
                } else {
                valid_IP = 1;
                }
    }
    while((!(valid_IP)))
    {
        int p;
        printf("IP Address: ");
        myGetLine(&ipaddr, &p, stdin);
        memcpy(ipaddr + p, "\0", 1);
        printf("Port: ");
        myGetLine(&port, &p, stdin);
        memcpy(port + 4, "\0", 1);
        if(!(SocketDemoUtils_populateAddreInfo(port, ipaddr, addr))){
                printf("Invalid IP address or port \n");
                } else {
                valid_IP = 1;
                }
    }
}


