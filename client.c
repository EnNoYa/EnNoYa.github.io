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


	if( argc < 3){       
	    perror("need server ip and main port");  
	    exit(1);  
	}
	
	
	
	
    //socket的建立
    int sockfd = 0,forClientSockfd = 0;
    char inputBuffer[256] = {};
    
    sockfd = socket(AF_INET , SOCK_STREAM , 0);
    


    //socket的連線

    struct sockaddr_in info,main_info,cli_info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;


    info.sin_addr.s_addr = inet_addr(argv[1]);
    info.sin_port = htons(8787);


    connect(sockfd,(struct sockaddr *)&info,sizeof(info));

	
    //傳送訊息
    char message[255]  ;
    strcpy(message, argv[2]);

    char receivemessage[255] = {};
    send(sockfd,message,sizeof(message),0);
    printf("send port\n");
    recv(sockfd,receivemessage,sizeof(receivemessage),0);
    close(sockfd);
    printf("port 8787 response: %s\n",receivemessage);
 
  
    sockfd=socket(AF_INET , SOCK_STREAM , 0);;
    int addrlen = sizeof(cli_info);
    bzero(&main_info,sizeof(main_info));

    main_info.sin_family = PF_INET;
    main_info.sin_addr.s_addr = INADDR_ANY;
    main_info.sin_port = htons(atoi(message));

    bind(sockfd,(struct sockaddr *)&main_info,sizeof(main_info));
    listen(sockfd,1);

    forClientSockfd = accept(sockfd,(struct sockaddr*) &cli_info, &addrlen);


    printf("Get from:%s\n",inet_ntoa(cli_info.sin_addr));

    recv(forClientSockfd,inputBuffer,sizeof(inputBuffer),0);
    
    printf("port %s recive:%s\n",message,inputBuffer);
   
  
    
    printf("close Socket\n");
    close(sockfd);
    return 0;
}

