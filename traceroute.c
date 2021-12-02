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



struct itimerval val_alarm = {
	.it_interval.tv_sec = 1,      
	.it_interval.tv_usec = 0,  
	.it_value.tv_sec = 0,  
	.it_value.tv_usec = 1  
};  

/*argc表示隱形程式命令列中引數的數目，argv是一個指向字串陣列指標，其中每一個字元對應一個引數*/
int main(int argc,char **argv)  
{  
	struct hostent		*host; /*該結構體屬於include<netdb.h>*/   
    int					on = 1;  
  
    if( argc < 2)/*判斷是否輸入了地址*/ 
	{       
		printf("Usage: %s hostname\n",argv[0]);  
		exit(1);  
    }  

	/*gethostbyname()返回對應於給定主機名的包含主機名字和地址資訊的結構指標,*/ 
    //if((host = getaddrinfo(argv[1])) == NULL)
    if((host = gethostbyname(argv[1])) == NULL)
	{     
		printf("usage:%s hostname/IP address\n", argv[0]);
		exit(1);  
    }  
  
    hostname = argv[1];	/*取出地址名*/  
  
	memset(&dest,0,sizeof dest);	/*將dest中前sizeof(dest)個位元組替換為0並返回s,此處為初始化,給最大記憶體清零*/  
	dest.sin_family=PF_INET;		/*PF_INET為IPV4，internet協議，在<netinet/in.h>中，地址族*/   
	dest.sin_port=ntohs(0);			/*埠號,ntohs()返回一個以主機位元組順序表達的數。*/  
	dest.sin_addr=*(struct in_addr *)host->h_addr_list[0];/*host->h_addr_list[0]是地址的指標.返回IP地址，初始化*/  

	/*PF_INEI套接字協議族，SOCK_RAW套接字型別，IPPROTO_ICMP使用協議，
	呼叫socket函式來建立一個能夠進行網路通訊的套接字。這裡判斷是否建立成功*/ 
	if((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{  
		perror("RAW socket created error");  
		exit(1);  
    }  

	/*設定當前套接字選項特定屬性值，sockfd套接字，IPPROTO_IP協議層為IP層，
	IP_HDRINCL套接字選項條目，套接字接收緩衝區指標，sizeof(on)緩衝區長度的長度*/ 
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));   

	/*getuid()函式返回一個呼叫程式的真實使用者ID,setuid()是讓普通使用者
	可以以root使用者的角色執行只有root帳號才能執行的程式或命令。*/ 
	setuid(getuid()); 
	pid = getpid(); /*getpid函式用來取得目前程序的程序識別碼*/  
  
	set_sighandler();/*對訊號處理*/  
	printf("Ping %s(%s): %d bytes data in ICMP packets.\n", argv[1], inet_ntoa(dest.sin_addr), datalen);  
  
	if((setitimer(ITIMER_REAL, &val_alarm, NULL)) == -1) /*定時函式*/  
	{
        bail("setitimer fails.");  
	}
  
    recv_reply(); /*接收icmp應答*/  
  
	return 0;  
}  


void send_udp(void)  
{  
    struct iphdr		*ip_hdr;   
    struct icmphdr		*icmp_hdr;  
    struct udphdr        *udp_hdr;
    int len;  
    int len1;  

   
    
    
        /*ip頭部*/  
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

    
    /*UDP頭部*/  
   

  
   
  

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

/*接收程式發出的icmp命令的應答*/  
void recv_reply()  
{  
	int			n;  
	int			len;  
    int			errno;  
   nsent=0;
    n = 0;
	nrecv = 0;  
    len = sizeof(from);  
  
    while(1)
	{  
		/*經socket接收資料,如果正確接收返回接收到的位元組數，失敗返回0.*/
		if((n=recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&from, &len))<0)
		{   
			if(errno==EINTR)  /*EINTR表示訊號中斷*/  
				continue;  
            bail("recvfrom error");  
        }  
  
		gettimeofday(&recvtime, NULL);   /*記錄收到應答的時間*/  

		if(handle_pkt())  {
			break;  }

    }  
  
    get_statistics(nsent, nrecv);     /*統計ping命令的檢測結果*/  
}  

 /*計算校驗和*/  
u16 checksum(u8 *buf,int len)  
{  
    u32 sum	= 0;  
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

/*ICMP應答訊息處理*/  
int handle_pkt()  
{  
	struct iphdr		*ip;  
    struct icmphdr		*icmp;  
    int					ip_hlen;  
    u16					ip_datalen; /*ip資料長度*/  
    double				rtt; /* 往返時間*/  
    struct timeval		*sendtime;  
  
    ip = (struct iphdr *)recvbuf;  
  
    ip_hlen = ip->hlen << 2;  
    ip_datalen = ntohs(ip->tot_len) - ip_hlen;  
  
    icmp = (struct icmphdr *)(recvbuf + ip_hlen);  
  

    if(checksum((u8 *)icmp, ip_datalen)) /*計算校驗和*/  
       return 0;  
  



	if(icmp->type==11){			nrecv++; 
		printf("%d bytes from %s:ttl=%d \n", 
			ip_datalen,					
			inet_ntoa(from.sin_addr),   
			gttl				
			);
	
	return 0;  }
	else if(icmp->type==3){			nrecv++; 
		printf("%d bytes from %s:ttl=%d \n",  
			ip_datalen,					
			inet_ntoa(from.sin_addr),   
			gttl				 
			);
	return 1;  }
  
}  

/*設定訊號處理程式*/  
void set_sighandler()  
{  
	act_alarm.sa_handler = alarm_handler;  
	/*sigaction()會依引數signum指定的訊號編號來設定該訊號的處理函式。引數signum指所要捕獲訊號或忽略的訊號，
	&act代表新設定的訊號共用體，NULL代表之前設定的訊號處理結構體。這裡判斷對訊號的處理是否成功。*/
    if(sigaction(SIGALRM, &act_alarm, NULL) == -1)    
	{
		bail("SIGALRM handler setting fails.");  
	}
  
	act_int.sa_handler = int_handler;  
    if(sigaction(SIGINT, &act_int, NULL) == -1)  
	{
		bail("SIGALRM handler setting fails.");  
	}
}  

 /*統計ping命令的檢測結果*/  
void get_statistics(int nsent,int nrecv)  
{  
    printf("--- %s ping statistics ---\n",inet_ntoa(dest.sin_addr)); /*將網路地址轉換成“.”點隔的字串格式。*/  
    printf("%d packets transmitted, %d received, %0.0f%% ""packet loss\n",  \
		nsent,nrecv,1.0*(nsent-nrecv)/nsent*100);  
}  

/*錯誤報告*/  
void bail(const char * on_what)  
{  
	/*:向指定的檔案寫入一個字串（不寫入字串結束標記符‘\0’）。成功寫入一個字串後，
	檔案的位置指標會自動後移，函式返回值為0；否則返回EOR(符號常量，其值為-1)。*/ 
    fputs(strerror(errno),stderr);   
    fputs(":",stderr);  
    fputs(on_what,stderr);  
    fputc('\n',stderr); /*送一個字元到一個流中*/  

    exit(1);  
}  
  
 /*SIGINT（中斷訊號）處理程式*/  
void int_handler(int sig)  
{  
    get_statistics(nsent,nrecv);    /*統計ping命令的檢測結果*/  
    close(sockfd);  /*關閉網路套接字*/  
    exit(1);  
}  

 /*SIGALRM（終止程序）處理程式*/  
void alarm_handler(int signo)  
{  
    send_udp();    /*傳送udp訊息*/  
  
}
