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
printf("Favsdfvfewf socket.\n");
    //socket的建立
    int sockfd = 0,forClientSockfd = 0;
    char inputBuffer[256] = {};
    printf("Fafewf socket.\n");
    sockfd = socket(AF_INET , SOCK_STREAM , 0);
    
	printf("%d\n",sockfd);
	printf("d\n");
  /*  if (sockfd == -1){
        printf("Fail to create a socket.");
    }*/

    //socket的連線
	printf("ssssend");
    struct sockaddr_in info,main_info,cli_info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;

    //localhost test
    info.sin_addr.s_addr = inet_addr("127.0.0.1");
    info.sin_port = htons(8700);


    int err = connect(sockfd,(struct sockaddr *)&info,sizeof(info));
    if(err==-1){
        printf("Connection error");
    }
	printf("send");

    //Send a message to server
    char message[] = {"1234"};
    char receiveMessage[100] = {};
    send(sockfd,message,sizeof(message),0);
    recv(sockfd,receiveMessage,sizeof(receiveMessage),0);

    printf("%s",receiveMessage);
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    sockfd=socket(AF_INET , SOCK_STREAM , 0);;
    int addrlen = sizeof(cli_info);
    bzero(&main_info,sizeof(main_info));

    main_info.sin_family = PF_INET;
    main_info.sin_addr.s_addr = INADDR_ANY;
    main_info.sin_port = htons(1234);
    bind(sockfd,(struct sockaddr *)&main_info,sizeof(main_info));
    listen(sockfd,1);

    //while(1){
        forClientSockfd = accept(sockfd,(struct sockaddr*) &cli_info, &addrlen);

        printf("Get:%x\n",cli_info.sin_addr.s_addr);
        printf("Get:%s\n",inet_ntoa(cli_info.sin_addr));
       // send(forClientSockfd,message,sizeof(message),0);
        //recv(forClientSockfd,inputBuffer,sizeof(inputBuffer),0);
        printf("Get:%s\n",inputBuffer);
    //}
    
    
    
    
    
    printf("close Socket\n");
    close(sockfd);
    return 0;
}
