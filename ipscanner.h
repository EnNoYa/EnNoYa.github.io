 
#define BUFSIZE 1500    //傳送快取最大值 
#define DEFAULT_DATA_LEN 56  //訊息資料預設大小 
  
//資料型別
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
    u8 hlen:4, ver:4;   //定義4-bit首部長度，和IP版本號為IPV4 
    u8 tos;             //8-bit服務型別TOS  
    u16 tot_len;        //16-bit總長度  
    u16 id;             //16-bit標誌位  
    u16 frag_off;       //3-bit標誌位 
    u8 ttl;             //8-bit生存週期  
    u8 protocol;        //8-bit協議  
    u16 check;          //16-bitIP首部校驗和  
    u32 saddr;          //32-bit源IP地址  
    u32 daddr;          //32-bit目的IP地址 
};  
  

char sendbuf[BUFSIZE];      //傳送字串陣列  
char recvbuf[BUFSIZE];      //接收字串陣列  
int nsent;                  //傳送的ICMP訊息序號  
int nrecv;                  //接收的ICMP訊息序號 
pid_t pid;                  //ping程式的程序PID
struct timeval recvtime;    //收到ICMP應答的時間戳
int sockfd;                 //傳送和接收原始套接字  
struct sockaddr_in dest;    //被ping的主機IP
struct sockaddr_in from;    //傳送ping應答訊息的主機IP
struct sigaction act_alarm;  
struct sigaction act_int;  
  
void send_icmp();               //傳送icmp訊息 
void recv_reply();              //接收icmp應答  
u16 checksum(u8 *buf, int len); //計算校驗和 
int handle_pkt();               //icmp應答訊息處理  
void get_statistics(int, int);  //發接統計 

