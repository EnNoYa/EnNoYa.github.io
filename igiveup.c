#include <stdlib.h>             /* For atof(), etc. */
#include <unistd.h>             /* For getpid(), etc. */
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <sys/time.h>
#include <resolv.h>
#include <netdb.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>



int send_probe(int, int, int);
int wait_for_reply(int, struct sockaddr_in *, struct timeval *);
void decode_icmp_ext(u_char *, int);
int packet_ok(u_char *, int, struct sockaddr_in *, int, int);
int tvsub(struct timeval *, struct timeval *);
void print_time(float *);
void print_from(struct sockaddr_in *);
int print(u_char *, int, struct sockaddr_in *);
int reduce_mtu(int);
int doqd(unsigned char *, int);
int dorr(unsigned char *, int, char **);
int doclass(unsigned char *, int);
int dordata(unsigned char *, int, int, int, char *, char **);
int dottl(unsigned char *,int);
int doname(unsigned char *, int, char *);
int dotype(unsigned char *, int);
void AbortIfNull (char *);
void print_ttl(int);
void print_packet(struct ip *, int);

extern  char *inet_ntoa();
extern  u_long inet_addr();

struct opacket {
        struct ip ip;
        union {
           struct udp_probe {
                  struct udphdr udp;
                  u_char seq;             /* sequence number of this packet */
                  u_char ttl;             /* ttl packet left with */
                  struct timeval tv;      /* time packet left */
              } udp_probe;
              struct icmp icmp_probe;
        } ip_payload;
};
