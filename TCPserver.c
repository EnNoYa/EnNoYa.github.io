#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 

int main(int argc , char *argv[])

{
    //socket的建立
    char inputBuffer[256] = {};
    char message[] = {"port 8700 Hi,this is server.\n"};
    int sockfd = 0,forClientSockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if (sockfd == -1){
        printf("Fail to create a socket.");
    }

    //socket的連線
    struct sockaddr_in serverInfo,clientInfo,main_info;
    int addrlen = sizeof(clientInfo);
    bzero(&serverInfo,sizeof(serverInfo));

    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(8700);
    bind(sockfd,(struct sockaddr *)&serverInfo,sizeof(serverInfo));
    listen(sockfd,5);

    while(1){
        forClientSockfd = accept(sockfd,(struct sockaddr*) &clientInfo, &addrlen);

        printf("Get:%x\n",clientInfo.sin_addr.s_addr);
        printf("Get:%s\n",inet_ntoa(clientInfo.sin_addr));
        recv(forClientSockfd,inputBuffer,sizeof(inputBuffer),0);     
        send(forClientSockfd,message,sizeof(message),0);

        
        printf("Get:%s\n",inputBuffer);
        
        if(strlen(inputBuffer)!=0){
       	printf("return\n");
       	//socket的連線
	    sockfd = socket(AF_INET , SOCK_STREAM , 0);
	    bzero(&main_info,sizeof(main_info));
	    main_info.sin_family = PF_INET;
printf("saaendback\n");
	    //localhost test
	    main_info.sin_addr.s_addr = clientInfo.sin_addr.s_addr;
	     main_info.sin_port = htons(atoi(inputBuffer));
 
printf("sendbacka\n");
	    int err = connect(sockfd,(struct sockaddr *)&main_info,sizeof(main_info));
	    if(err==-1){
		printf("Connection error");
	    }

printf("sendsback\n");
	    //Send a message to server
	    char message[] = {"cookie"};
	    send(sockfd,message,sizeof(message),0);
	printf("sendback\n");
        }
    }
    return 0;
}
