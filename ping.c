#include<stdio.h>  
#include<stdlib.h>  
#include<sys/time.h>  /*是Linux系統的日期時間標頭檔案*/  
#include<unistd.h>    /*　是POSIX標準定義的unix類系統定義符號常量的標頭檔案，包含了許多UNIX系統服務的函式原型，例如read函式、write函式和getpid函式*/  
#include<string.h>  
#include<sys/socket.h>    /*對與引用socket函式必須*/  
#include<sys/types.h>  
#include<netdb.h> /*定義了與網路有關的結構，變數型別，巨集，函式。函式gethostbyname()用*/  
#include<errno.h> /*sys/types.h中文名稱為基本系統資料型別*/  
#include<arpa/inet.h> /*inet_ntoa()和inet_addr()這兩個函式，包含在 arpa/inet.h*/  
#include<signal.h>    /*程序對訊號進行處理*/  
#include<netinet/in.h>    /*網際網路地址族*/  
  
#include"ping.h"  
#define IP_HSIZE sizeof(struct iphdr)   /*定義IP_HSIZE為ip頭部長度*/  
#define IPVERSION  4   /*定義IPVERSION為4，指出用ipv4*/  

/*設定的時間是一個結構體，倒計時設定，重複倒時，超時值設為1秒*/  
struct itimerval val_alarm = {
	.it_interval.tv_sec = 1,      
	.it_interval.tv_usec = 0,  
	.it_value.tv_sec = 0,  
	.it_value.tv_usec = 1  
};  



static int gttl=0;
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
        gttl=0;
	set_sighandler();/*對訊號處理*/  
	printf("Ping %s(%s): %d bytes data in ICMP packets.\n", argv[1], inet_ntoa(dest.sin_addr), datalen);  
  
	if((setitimer(ITIMER_REAL, &val_alarm, NULL)) == -1) /*定時函式*/  
	{
        bail("setitimer fails.");  
	}
  
    recv_reply(); /*接收ping應答*/  
  
	return 0;  
}  

/*傳送ping訊息*/  
void send_ping()  
{  
    struct iphdr		*ip_hdr;   /*iphdr為IP頭部結構體*/  
    struct icmphdr		*icmp_hdr;   /*icmphdr為ICMP頭部結構體*/  
    int					len;  
    int					len1;  

	/*ip頭部結構體變數初始化*/  
    ip_hdr=(struct iphdr *)sendbuf; /*字串指標*/     
    ip_hdr->hlen=sizeof(struct iphdr)>>2;  /*頭部長度*/  
    ip_hdr->ver=IPVERSION;   /*版本*/  
    ip_hdr->tos=0;   /*服務型別*/  
    ip_hdr->tot_len=IP_HSIZE+ICMP_HSIZE+datalen; /*報文頭部加資料的總長度*/  
    ip_hdr->id=0;    /*初始化報文標識*/  
    ip_hdr->frag_off=0;  /*設定flag標記為0*/  
    ip_hdr->protocol=IPPROTO_ICMP;/*運用的協議為ICMP協議*/  
    ip_hdr->ttl=++gttl; /*一個封包在網路上可以存活的時間*/  
    ip_hdr->daddr=dest.sin_addr.s_addr;  /*目的地址*/  
    len1=ip_hdr->hlen<<2;  /*ip資料長度*/  
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
  
    sendto(sockfd,sendbuf,len,0,(struct sockaddr *)&dest,sizeof (dest)); /*經socket傳送資料*/  
}  

/*接收程式發出的ping命令的應答*/  
void recv_reply()  
{  
	int			n;  
	int			len;  
    int			errno;  
  
    n = 0;
	nrecv = 0;  
    len = sizeof(from);   /*傳送ping應答訊息的主機IP*/  
  
    while(nrecv < 4)
	{  
		/*經socket接收資料,如果正確接收返回接收到的位元組數，失敗返回0.*/
		if((n=recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&from, &len))<0)
		{   
			if(errno==EINTR)  /*EINTR表示訊號中斷*/  
				continue;  
            bail("recvfrom error");  
        }  
  
		gettimeofday(&recvtime, NULL);   /*記錄收到應答的時間*/  

		if(handle_pkt())    /*接收到錯誤的ICMP應答資訊*/  
			continue;  

		nrecv++;  
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
       return -1;  
  
	if(icmp->icmp_id != pid)  
		return -1;  

	sendtime = (struct timeval *)icmp->data; /*傳送時間*/  
	rtt = ((&recvtime)->tv_sec - sendtime->tv_sec) * 1000 + ((&recvtime)->tv_usec - sendtime->tv_usec)/1000.0; /* 往返時間*/  
	/*列印結果*/  
	printf("%d bytes from %s:icmp_seq=%u ttl=%d rtt=%.3f ms\n",  \
			ip_datalen,					/*IP資料長度*/  
			inet_ntoa(from.sin_addr),   /*目的ip地址*/  
			icmp->icmp_seq,				/*icmp報文序列號*/  
			ip->ttl,					/*生存時間*/  
			rtt);						/*往返時間*/  

	return 0;  
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
    send_ping();    /*傳送ping訊息*/  
  
}
