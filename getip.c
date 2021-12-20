#include<stdio.h>  
#include<stdlib.h>  
#include<sys/time.h>  
#include<unistd.h>    
#include<string.h>  
#include<sys/socket.h>    
#include<sys/types.h>  
#include<netdb.h> 
#include<errno.h> 
#include<arpa/inet.h> 
#include<signal.h>    
#include<netinet/in.h>    
#include<netinet/udp.h>  
#include"traceroute.h"  
#define IP_HSIZE sizeof(struct iphdr)   
#define IPVERSION  4   

int
main(int argc, char **argv)
{
	struct ifreq ifr;
	int msockfd;


	msockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	strcpy(ifr.ifr_name, hostname);
	ioctl(msockfd, SIOCGIFADDR, &ifr);  
	    strcpy(myip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)); //get IP

	if(ioctl(msockfd, SIOCGIFNETMASK, &ifr)< 0){ //get Mask
	close(msockfd);
	return 0;
	}
	strcpy(mymask, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	
	return 0;
}
