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


static int gttl=0;
static int pport=33434;
static int maxttl=0;


struct itimerval val_alarm = {
  .it_interval.tv_sec = 1,      
  .it_interval.tv_usec = 0,  
  .it_value.tv_sec = 0,  
  .it_value.tv_usec = 1  
};  


int main(int argc,char **argv){  
  struct hostent    *host; 
  int         on = 1;  
  
  
  if( argc < 3){       
    printf("need TTl and hostname");  
    exit(1);  
  }  
  
  if( argc < 3){       
    printf("need hostname");  
    exit(1);  
  }  


  if((host = gethostbyname(argv[2])) == NULL){     
    printf("DNS not found");
    exit(1);  
  }  
  
  hostname = argv[2]; 
  maxttl=atoi(argv[1]);
  memset(&dest,0,sizeof dest);  
  dest.sin_family=PF_INET;      
  dest.sin_port=ntohs(0);     
  dest.sin_addr=*(struct in_addr *)host->h_addr_list[0];


  if((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){  
    perror("RAW socket created error");  
    exit(1);  
  }  

 
  setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));   

  setuid(getuid()); 
  pid = getpid(); 
  
  set_sighandler();

  printf("Tracerouting %s(%s): %d bytes data in UDP packets.\n", argv[2], inet_ntoa(dest.sin_addr), datalen);  
  
  setitimer(ITIMER_REAL, &val_alarm, NULL); //定時  

  
  recv_reply(); //接收icmp
  
  return 0;  
}  


void send_udp(void){  
    struct iphdr    *ip_hdr;   
    struct icmphdr  *icmp_hdr;  
    struct udphdr   *udp_hdr;
    int len;  
    int len1;  

      
    //ip頭部
    ip_hdr=(struct iphdr *)sendbuf; 
    ip_hdr->hlen=sizeof(struct iphdr)>>2;  
    ip_hdr->ver=IPVERSION;    
    ip_hdr->tos=0;  
    ip_hdr->tot_len=IP_HSIZE+sizeof(struct udphdr)+datalen; 
    ip_hdr->id=0;    
    ip_hdr->frag_off=0; 
    ip_hdr->protocol=IPPROTO_UDP;
    ip_hdr->ttl=++gttl;
    ip_hdr->daddr=dest.sin_addr.s_addr;  
    len1=ip_hdr->hlen<<2;  

    
    //UDP頭部 
    udp_hdr=(struct udphdr *)(sendbuf+len1);
    udp_hdr->source=htons((getpid() & 0xffff) | 0x8000);
    udp_hdr->dest=htons(++pport);
    udp_hdr->len=htons(64);

    len=ip_hdr->tot_len; 
    udp_hdr->check=0;
    udp_hdr->check=checksum((u8 *)udp_hdr,len);  

    sendto(sockfd,sendbuf,len,0,(struct sockaddr *)&dest,sizeof (dest)); 
    
    nsent++;
}  

//接收icmp
void recv_reply(){  
  int     n;  
  int     len;  
  int     errno;  
  nsent=0;
  n = 0;
  nrecv = 0;  
  len = sizeof(from);  
  
  while(1){  

    //接收資料
    recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&from, &len);
  
    //處理資料
    if(handle_pkt()||maxttl<=gttl)  {
      break;  
    }
  }    
  get_statistics(nsent, nrecv);     //發接統計  
}  

 //計算校驗和
u16 checksum(u8 *buf,int len)  
{  
    u32 sum = 0;  
    u16 *cbuf;  
  
    cbuf = (u16 *)buf;  
  
    while(len > 1)
  {  
    sum += *cbuf++;  
    len -= 2;  
    }  
  
    if(len)
  {
        sum += *(u8 *)cbuf;  
  }
  
  sum = (sum >> 16) + (sum & 0xffff);  
  sum += (sum >> 16);  

  return ~sum;  
}  

//ICMP處理
int handle_pkt(){  
  struct iphdr    *ip;  
  struct icmphdr    *icmp;  
  int         ip_hlen;  
  u16         ip_datalen;    

  ip = (struct iphdr *)recvbuf;  

  ip_hlen = ip->hlen << 2;  
  ip_datalen = ntohs(ip->tot_len) - ip_hlen;  

  icmp = (struct icmphdr *)(recvbuf + ip_hlen);  


  if(checksum((u8 *)icmp, ip_datalen)){
    return 0;  
  }
  



  if(icmp->type==11){ 
    nrecv++; 
    printf("%d bytes from %s:ttl=%d \n",ip_datalen,inet_ntoa(from.sin_addr),gttl);
  
    return 0;
  }
  else if(icmp->type==3){ 
    nrecv++; 
    printf("%d bytes from %s:ttl=%d \n",ip_datalen,inet_ntoa(from.sin_addr),gttl);
    return 1;  
  }
  
}  

///設定訊號處理
void set_sighandler(){  
  act_alarm.sa_handler = alarm_handler;  
  
  if(sigaction(SIGALRM, &act_alarm, NULL) == -1){
		
	}

	act_int.sa_handler = int_handler;  
  if(sigaction(SIGINT, &act_int, NULL) == -1){
	
	}

}  

 //發接統計  
void get_statistics(int nsent,int nrecv)  
{  
    printf("--------------------\n"); 
    printf("%d packets transmitted, %d received, %0.0f%% ""packet loss\n",  \
    nsent,nrecv,1.0*(nsent-nrecv)/nsent*100);  
}  

  
 //SIGINT中斷訊號 
void int_handler(int sig)  
{  
    get_statistics(nsent,nrecv);    
    close(sockfd);   
    exit(1);  
}  

 //SIGALRM終止程序  
void alarm_handler(int signo)  
{  
    send_udp();    
  
}
