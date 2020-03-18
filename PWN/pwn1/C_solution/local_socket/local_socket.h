#ifndef LOCAL_SOCKET_H
#define LOCAL_SOCKET_H

#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int SocketDemoUtils_createTcpSocket();
int SocketDemoUtils_populateAddreInfo(char *port, char *ipAddr, struct sockaddr_in *addr);
int SocketDemoUtils_bind(int sockFd, struct sockaddr_in *addr);
int SocketDemoUtils_listen(int sockFd);
int SocketDemoUtils_accept(int sockFd, struct sockaddr_in *addr);
int SocketDemoUtils_recv(int sockFd, char *buf, int chunk, int waitFlag);
int SocketDemoUtils_send(int sockFd, char *buf, int numBytes);
int myGetLine(char ** lineptr, int * n, FILE *stream);
char * read_message(int chunk, int clientFd, char* buf);
void setAddrInfo(int argc, char const *argv[], char * port, char * ipaddr, struct sockaddr_in *addr);
#endif
