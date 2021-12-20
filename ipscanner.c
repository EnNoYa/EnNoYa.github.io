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
#include <sys/ioctl.h>
#include <net/if.h>
#include"ipscanner.h"  
#define IP_HSIZE sizeof(struct iphdr)   
#define IPVERSION  4   

//#define REV(X) ((( X >> 28 )& 0x0000000f ) |(( X >> 20 ) & 0x000000f0)|(( X  >> 12) & 0x00000f00)|(( X >> 4 ) & 0x0000f000)|(( X << 4 ) & 0x000f0000)|(( X << 12 ) & 0x00f00000)|(( X << 20 ) & 0x0f000000)|(( X << 28 ) & 0xf0000000 ))

#define REV(X) ((( X >> 24 )& 0x000000ff ) |(( X  >> 8) & 0x0000ff00)|(( X << 8 ) & 0x00ff0000)|(( X << 24 ) & 0xff000000))

static int timeout=100;



int main(int argc,char **argv){  
  struct hostent    *host; 
  int         on = 1;  

  
  if( argc < 5){       
    perror("need interface and timeouttime");  
    exit(1);  
  }  


    int fd_arp;      /* socket fd for receive packets */
    u_char *ptr;
    struct in_addr myip, mymask,subnetip,networkip;
    struct ifreq ifr; /* ifr structure */
    struct sockaddr_in *sin_ptr;
	
    timeout=atoi(argv[4]);

    strcpy(ifr.ifr_name, argv[2]);

    fd_arp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);


    /* get ip address of my interface */
	ioctl(fd_arp, SIOCGIFADDR, &ifr);
        sin_ptr = (struct sockaddr_in *)&ifr.ifr_addr;
        myip = sin_ptr->sin_addr;
    

    /* get network mask of my interface */
	ioctl(fd_arp, SIOCGIFNETMASK, &ifr) ;
	sin_ptr = (struct sockaddr_in *)&ifr.ifr_addr;
	mymask = sin_ptr->sin_addr;
    
    
  if((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){  
    perror("RAW socket created error");  
    exit(1);  
  }  
 
  setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));   

  setuid(getuid()); 
  pid = getpid();  
    
    

    
  int i=0x0;
  networkip.s_addr=myip.s_addr&mymask.s_addr;
  for(i;i<REV(0xffffffff^mymask.s_addr);++i)
  {
  	if(i==REV(myip.s_addr&(mymask.s_addr^0xffffffff))){continue;}


    subnetip.s_addr=REV(i)|networkip.s_addr;


  memset(&dest,0,sizeof dest);  
  dest.sin_family=PF_INET;      
  dest.sin_port=ntohs(0);     
  dest.sin_addr=subnetip;
  
    printf("PING %s (data size = %d, id = , seq = %d , timeout = %d ms)\n", inet_ntoa(dest.sin_addr), datalen,i+1,timeout); 
  send_icmp();  
  

  }

  



 

  
  recv_reply(); //接收icmp
  
  return 0;  
}  


void send_icmp(void){  
    struct iphdr    *ip_hdr;   
    struct icmphdr  *icmp_hdr;  

    int len;  
    int len1;  

      
    //ip頭部
    ip_hdr=(struct iphdr *)sendbuf; 
    ip_hdr->hlen=sizeof(struct iphdr)>>2;  
    ip_hdr->ver=IPVERSION;    
    ip_hdr->tos=0;  
    ip_hdr->tot_len=IP_HSIZE+sizeof(struct icmphdr)+datalen; 
    ip_hdr->id=0;    
    ip_hdr->frag_off=0; 
    ip_hdr->protocol=IPPROTO_ICMP;
    ip_hdr->ttl=1;
    ip_hdr->daddr=dest.sin_addr.s_addr;  
    len1=ip_hdr->hlen<<2;  

    /*ICMP頭部結構體變數初始化*/  
    icmp_hdr=(struct icmphdr *)(sendbuf+len1);  /*字串指標*/  
    icmp_hdr->type=8;    /*初始化ICMP訊息型別type*/  
    icmp_hdr->code=0;    /*初始化訊息程式碼code*/  
    icmp_hdr->icmp_id=pid;   /*把程序標識碼初始給icmp_id*/  
    icmp_hdr->icmp_seq=nsent++;  /*傳送的ICMP訊息序號賦值給icmp序號*/      
    memset(icmp_hdr->data,0xff,datalen);  /*將datalen中前datalen個位元組替換為0xff並返回icmp_hdr-dat*/    
  
    gettimeofday((struct timeval *)icmp_hdr->data,NULL); /* 獲取當前時間*/  
  
    len=ip_hdr->tot_len; /*報文總長度賦值給len變數*/  
    icmp_hdr->checksum=0;    /*初始化*/  
    icmp_hdr->checksum=checksum((u8 *)icmp_hdr,len);  /*計算校驗和*/  


    sendto(sockfd,sendbuf,len,0,(struct sockaddr *)&dest,sizeof (dest)); 
    
    nsent++;
}  

//接收icmp
void recv_reply()  
{  
    int			n;  
	int			len;  
    int			errno;  
  
    n = 0;
    nrecv = 0;  
    len = sizeof(from);   /*傳送ping應答訊息的主機IP*/  
  
    while(1)
	{  
		/*經socket接收資料,如果正確接收返回接收到的位元組數，失敗返回0.*/
 	n=recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&from, &len);

  
	gettimeofday(&recvtime, NULL);   /*記錄收到應答的時間*/  

		if(handle_pkt())  {
			continue;  }

		nrecv++;  
    }  
  
    get_statistics(nsent, nrecv);     /*統計ping命令的檢測結果*/  
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
  double				rtt; /* 往返時間*/  
  struct timeval		*sendtime; 
  int         ip_hlen;  
  u16         ip_datalen;    

  ip = (struct iphdr *)recvbuf;  

  ip_hlen = ip->hlen << 2;  
  ip_datalen = ntohs(ip->tot_len) - ip_hlen;  

  icmp = (struct icmphdr *)(recvbuf + ip_hlen);  


  if(checksum((u8 *)icmp, ip_datalen)){
    return 1;  
  }
  
   sendtime = (struct timeval *)icmp->data; /*傳送時間*/  
	rtt = ((&recvtime)->tv_sec - sendtime->tv_sec) * 1000 + ((&recvtime)->tv_usec - sendtime->tv_usec)/1000.0; /* 往返時間*/  


  if(icmp->type==0){ 
    nrecv++; 
    printf("Reply from %s time: %lf \n",inet_ntoa(from.sin_addr),rtt);
  
    return 0;
  }
  return 1;
  
}  



 //發接統計  
void get_statistics(int nsent,int nrecv)  
{  
    printf("--------------------\n"); 
    printf("%d packets transmitted, %d received, %0.0f%% ""packet loss\n",  \
    nsent,nrecv,1.0*(nsent-nrecv)/nsent*100);  
}  

  

