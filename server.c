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
    char message[] = {"port 8787  server.\n"};
    int sockfd = 0,forClientSockfd = 0,backsockfd=0;
    
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    //socket的連線
    struct sockaddr_in serverInfo,main_info,clientInfo;
     
    int addrlen = sizeof(clientInfo);
    
    bzero(&serverInfo,sizeof(serverInfo));

    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(8787);
    
    bind(sockfd,(struct sockaddr *)&serverInfo,sizeof(serverInfo));
    listen(sockfd,5);
 
    while(1){
        printf("listening\n");

        forClientSockfd = accept(sockfd,(struct sockaddr*) &clientInfo, &addrlen);



        recv(forClientSockfd,inputBuffer,sizeof(inputBuffer),0);     
        send(forClientSockfd,message,sizeof(message),0);

        
        printf("Target ip port:%s %s\n",inet_ntoa(clientInfo.sin_addr),inputBuffer);
        sleep(1);
        
        if(strlen(inputBuffer)!=0){
      
       	//main socket的連線
	    backsockfd = socket(AF_INET , SOCK_STREAM , 0);
	    bzero(&main_info,sizeof(main_info));
	    main_info.sin_family = PF_INET;

	    main_info.sin_addr.s_addr = clientInfo.sin_addr.s_addr;
	    main_info.sin_port = htons(atoi(inputBuffer));
 

	    connect(backsockfd,(struct sockaddr *)&main_info,sizeof(main_info));

 	   printf("send cookie\n");
	    //送回客戶端
	    char message[] = {"cookie"};
	    send(backsockfd,message,sizeof(message),0);
           inputBuffer[0] = '\0';
           close(backsockfd);
        }

    }
    return 0;
}

