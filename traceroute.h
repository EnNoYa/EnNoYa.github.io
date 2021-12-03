 
#define BUFSIZE 1500    //傳送快取最大值 
#define DEFAULT_LEN 56  //訊息資料預設大小 
  
//資料類型別名 
typedef unsigned char u8;  
typedef unsigned short u16;  
typedef unsigned int u32;  
    
struct icmphdr {  
    u8 type;     
    u8 code;    
    u16 checksum;  
    union{  
        struct{  
        u16 id;  
        u16 sequence;  
    }echo;  
    u32 gateway;  
    struct{  
        u16 unsed;  
        u16 mtu;  
    }frag;   
    }un;  

    u8 data[0];  
#define icmp_id un.echo.id  
#define icmp_seq un.echo.sequence  
};  
#define ICMP_HSIZE sizeof(struct icmphdr)  
 
struct iphdr {  
    u8 hlen:4, ver:4;   //定義4位首部長度，和IP版本號為IPV4 
    u8 tos;				//8位服務型別TOS  
    u16 tot_len;		//16位總長度  
    u16 id;				//16位標誌位  
    u16 frag_off;		//3位標誌位 
    u8 ttl;				//8位生存週期  
    u8 protocol;		//8位協議  
    u16 check;			//16位IP首部校驗和  
    u32 saddr;			//32位源IP地址  
    u32 daddr;			//32位目的IP地址 
};  
  
char *hostname;				//目標的主機名
int datalen = DEFAULT_LEN;  //ICMP訊息攜帶的資料長度  
char sendbuf[BUFSIZE];      //傳送字串陣列  
char recvbuf[BUFSIZE];      //接收字串陣列  
int nsent;					//傳送的ICMP訊息序號  
int nrecv;					//接收的ICMP訊息序號 
pid_t pid;					//ping程式的程序PID
struct timeval recvtime;    //收到ICMP應答的時間戳
int sockfd;					//傳送和接收原始套接字  
struct sockaddr_in dest;    //被ping的主機IP
struct sockaddr_in from;    //傳送ping應答訊息的主機IP
struct sigaction act_alarm;  
struct sigaction act_int;  
  
  
void alarm_handler(int);		//SIGALRM處理程式 
void int_handler(int);			//SIGINT處理程式 
void set_sighandler();			//設定訊號處理程式  
void send_udp();				//傳送udp訊息 
void recv_reply();				//接收icmp應答  
u16 checksum(u8 *buf, int len); //計算校驗和 
int handle_pkt();				//ICMP應答訊息處理  
void get_statistics(int, int);  //發接統計 

