#define V630 /* V6.3.0 */

#define TRACE_TOS 1
#define SPRAY
#define FIXT
#ifndef lint
static char *rcsid =
   "@(#)$Header: Etraceroute.c,v 6.3.9 2003/07/15 gavron(gavron@wetwork.net)";
#endif
#ifdef TRACE_TOS
#define TR_VERSION "6.3.9 GOLD+emf_prototrace0.2+sl_tostrace0.1"
#else /* not TRACE_TOS */
#define TR_VERSION "6.3.9 GOLD+emf_prototrace0.2"
#endif /* not TRACE_TOS */


#include <stdio.h>
#include <math.h>

 
#define IP_VERSION 4    /* We can't work with anything else... */
#define CISCO_ICMP 1    /* We check for loss+unreachables = probes */

#ifdef __decc           /* DEC C wants strings.h to be called string.h */
#define STRING
#define NOINDEX
#define NOBZERO
#endif

#ifdef SOLARIS          /* Solaris has UCB stuff gone, and POSIX resolver */
#define SUN_WO_UCB
#define POSIX
#endif

#ifdef SUN_WO_UCB
#define STRING
#define NOINDEX
#include <signal.h>
#endif

#ifdef _AIX             /* Aix has its own set of fd_* macros */
#include <signal.h>
#include <sys/select.h>
#endif

#ifdef STRING
#include <string.h>
#else /* ! STRING */
#include <strings.h>
#endif /* STRING */

#include <sys/param.h>

#ifdef NOINDEX
#define index(x,y) strchr(x,y)  /* Use ansi strchr() if no index() */
#endif /* NOINDEX */

#ifndef bzero
#ifdef NOBZERO
#define bzero(x,y) memset((void *)x,(int)0,(size_t) y)
#define bcopy(x,y,z) memcpy((void *)y, (const void *)x, (size_t) z)
#endif /* NOBZERO */
#endif /* bzero*/

#include <stdlib.h>             /* For atof(), etc. */
#include <unistd.h>             /* For getpid(), etc. */

/* The VMS stuff follows */
#ifdef  vms
typedef unsigned short u_int16_t;
/* typedef unsigned long u_int32_t; /* Got added to Multinet */
#include "snprintf.c"		/* VMS doesn't have snprintf */
pid_t decc$getpid(void);        /* Just don't ask...*/
#define getpid decc$getpid      /* Really... don't ask.*/
#define perror socket_perror    /* MultiNet wants this */
#ifdef MULTINET_V3
#define errno socket_errno      /* MultiNet wants this */
#include "multinet_root:[multinet.include]errno.h"
#else /* MULTINET_V4 */
#define MULTINET_V4
#include <errno.h>
#ifdef errno
#undef errno
#include "multinet_root:[multinet.include]errno.h"
#define errno socket_errno      /* Multinet 4.1 */
#endif /* errno defined */
#endif /* MULTINET_V3 */
#define write socket_write      /* MultiNet wants this */
#define read socket_read        /* MultiNet wants this */
#define close socket_close      /* MultiNet wants this */
#include <signal.h>
#ifdef __alpha
#define BYTE_ORDER 1234         /* The include files for Alpha are bad. */
#define LITTLE_ENDIAN 1234      /* They incorrectly swap ip_v and ip_hl */
#define BIG_ENDIAN 4321         /* Which makes packet_ok fail.  New diag */
#endif /* __alpha */            /* Info says:  packet version not 4: 5 */
#ifdef VMS_CLD                  /* use separate qualifers instead of options */
#include "clis.h"
#else /* No CLD */
int fixargs(int *, char **, char **);
#endif /* VMS_CLD */
#else /* not VMS */
#include <errno.h>
#endif  /* vms */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <sys/time.h>


#include <resolv.h>


#ifdef __linux__                /* Wrapping this may be excessive */
#define __FAVOR_BSD 1           /* 6.3.0 - add value 1 */
#endif

#ifdef __linux__
#define BYTESWAP_IP_FLAGS
#endif

#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifndef __linux__
#include <netinet/ip_var.h>
#else /* __linux__ */
#include <sys/time.h>
/* IRD #include <netinet/if_tr.h> */
#endif /* __linux__ */
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <ctype.h>
#include <math.h>               /* After resolv.h for gcc2.7/sun __p redef */
#include <signal.h>

#ifdef SOLARIS
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
#endif /* SOLARIS */

#ifndef NO_PROTOTYPES           /* By default, have prototypes */
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
#ifdef V630
void cksum(u_int16_t *, int, volatile u_int16_t *);
#endif /* V630 */
#endif /* NO_PROTOTYPES */

#define MAXPACKET       65535   /* max ip packet size */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  64
#endif

#define SIZEOFstructip sizeof(struct ip)

#ifndef FD_SET
#define NFDBITS         (8*sizeof(fd_set))
#define FD_SETSIZE      NFDBITS
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif

#define Fprintf (void)fprintf
#define Sprintf (void)sprintf
#define Printf (void)printf

#define NOERR(val,msg) {if (((int)(val)) < 0) {perror(msg);exit(1);}}

#ifndef NO_SOA_RECORD
#define NO_SOA_RECORD "no SOA record"
#endif

/*  For some reason, IP_HDRINCL and LSRR don't interact well on SGI;
 *  so turn it off:  */
#ifdef sgi
#undef IP_HDRINCL
#endif

#ifndef vms
extern  int errno;
#endif

extern  char *inet_ntoa();
extern  u_long inet_addr();

#ifndef ULTRIX43
char *index(const char *string, int character);
#endif

#ifdef V630
#ifndef __linux__
void halt();	/* signal handler */
#endif /* __linux__ */
#else /* ! V630 */
void halt();   /* signal handler */
#endif /* ! V630 */

/*
 * format of a probe packet.
 */
struct opacket {
        struct ip ip;
#ifndef V630
        struct udphdr udp;
        u_char seq;             /* sequence number of this packet */
        u_char ttl;             /* ttl packet left with */
        struct timeval tv;      /* time packet left */
#else /* V6.3.0: */
        union {
           struct udp_probe {
                  struct udphdr udp;
                  u_char seq;             /* sequence number of this packet */
                  u_char ttl;             /* ttl packet left with */
                  struct timeval tv;      /* time packet left */
              } udp_probe;
              struct icmp icmp_probe;
        } ip_payload;
#endif /* V6.3.0 */
};

#ifdef SPRAY
/*
 * format of a spray data cell.
 */
#define SPRAYMAX 512            /* We'll only do up to 512 packets at once */
struct {
        u_long  dport;          /* check for matching dport */
        u_char  ttl;            /* ttl we sent it to */
        u_char  type;           /* icmp response type */
        struct  timeval out;    /* time packet left */
        struct  timeval rtn;    /* time packet arrived */
        struct  sockaddr_in from; /* whom from */
} spray[SPRAYMAX];
unsigned *spray_rtn[SPRAYMAX];       /* See which TTLs have responded */
unsigned spray_target;               /* See which TTL the host responds on */
unsigned spray_max;                  /* See which is the highest TTL we've seen */
unsigned spray_min;                  /* See smallest host-returned TTL */
int spray_total;                /* total of responses seen */
int spray_mode =0;              /* By default, turned off */
#endif /* SPRAY */

#ifdef TRACE_TOS
static u_char last_tos;
static u_char tos_at_this_hop;
#endif /* TRACE_TOS */

u_char  packet[512];            /* last inbound (icmp) packet */
struct opacket  *outpacket;     /* last output packet */
char *inetname();
u_char  optlist[MAX_IPOPTLEN];  /* IP options list  */
int _optlen;
struct icmp *icp;               /* Pointer to ICMP header in packet */

int s;                          /* receive (icmp) socket file descriptor */
int sndsock;                    /* send (udp) socket file descriptor */
#if defined(FREEBSD) || defined(__linux__)
struct timezone tz;
#else
unsigned long   tz;             /* leftover */
#endif
struct sockaddr whereto;        /* Who to try to reach */
struct sockaddr_in addr_last;   /* last printed address */
int datalen;                    /* How much data */

char *source = 0;
char *hostname;
char hnamebuf[MAXHOSTNAMELEN];

unsigned nprobes = 3;
unsigned min_ttl = 1;
unsigned max_ttl = 64;
u_short ident;
u_short port = 32768+666;       /* start udp dest port # for probe packets */
u_short sport = 1000;           /* source port ... */

/* Remap a subset of standard socket options so that we're able to OR
 * them together.
 */
enum trt_socket_options {
	TRT_DEBUG 	= (1<<0),
	TRT_DONTROUTE 	= (1<<1)
};

enum trt_socket_options options; /* socket options */
int verbose;
int mtudisc=0;                  /* do MTU discovery in path */
int pingmode=0;                 /* replacing ping functionality? */
#ifndef vms
float waittime = 3.0;           /* time to wait for response (in seconds) */
#else /* vms */
double waittime = 3.0;
#endif
int nflag;                      /* print addresses numerically */

#define TERM_SIZE 32            /* Size of line terminator... */
char terminator[TERM_SIZE];     /* Line terminator... */
int haltf=0;                    /* signal happened */
int ppdelay=1;                  /* we normally want per-packet delay */
int pploss=0;                   /* we normally don't want packet loss */
int lost;                       /* how many packets did we not get back */
double throughput;              /* percentage packets not lost */
int consecutive=0;              /* the number of consecutive lost packets */
int automagic=0;                /* automatically quit after 10 lost packets? */
int hurry_mode=0;               /* only do one on successful ttls */
int utimers=0;                  /* Print timings in microseconds */
int dns_owner_lookup=0;         /* Look up owner email in DNS */
int as_lookup=0;                /* Look up AS path in routing registries */
int got_there;
int unreachable;
int response_mask = 0;
int mtu, new_mtu = 0;

/*  The following heuristic taken from RFC1191  */
int mtuvals[]={MAXPACKET, 32000, 17914, 8166, 4352, 2002, 1492,
   1006, 508, 296, 68, -1};

char nullstring[] = "<NONE>";

char usage[] = "%s: TrACESroute\nUsage: traceroute [-adnruvAMOPQU] [-w wait] [-S start_ttl] [-m max_ttl] [-p port#] [-q nqueries] [-g gateway] [-t tos] [-s src_addr] [-g router] [-I proto] host [data size]\n\
      -a: Abort after 10 consecutive hops without answer\n\
      -d: Socket level debugging (root only)\n\
      -g: Use this gateway as an intermediate hop (uses LSRR)\n\
      -S: Set start TTL (default 1)\n\
      -m: Set maximum TTL (default 30)\n\
      -n: Report IP addresses only (not hostnames)\n\
      -p: Use an alternate UDP port\n\
      -q: Set the number of queries at each TTL (default 3)\n\
      -r: Set Dont Route option\n\
      -s: Set your source address\n\
      -t: Set the IP TOS field (default 0)\n\
      -u: Use microsecond timestamps\n\
      -v: Verbose\n\
      -w: Set timeout for replies (default 5 sec)\n\
      -A: Report AS# at each hop (from GRR)\n\
      -I: use this IP protocol instead of UDP\n\
      -M: Do RFC1191 path MTU discovery\n\
      -O: Report owner at each hop (from DNS)\n\
      -P: Parallel probing\n\
      -Q: Report delay statistics at each hop (min/avg+-stddev/max) (ms)\n\
      -T: Terminator (line end terminator)\n\
      -U: Go to next hop on any success\n";

float deltaT();

/* cph 2000/10/15 - move raw socket code to separate function */
void get_sockets(void)
{
	struct protoent *pe;

	if ((pe = getprotobyname("icmp")) == NULL) {
		Fprintf(stderr, "icmp: unknown protocol\n");
		exit(10);
	}
	if ((s = socket(AF_INET, SOCK_RAW, pe->p_proto)) < 0) {
		perror("traceroute: icmp socket");
		exit(5);
	}
	if ((sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("traceroute: raw socket");
		exit(5);
	}
}

main(argc, argv)
        int argc;
        char *argv[];
{
        struct sockaddr_in from;
        char **av = argv;
#ifdef VMS_CLD
        char *ptr;
#endif /* VMS_CLD */
#ifdef SPRAY
        float ddt=0;    /* Delta delta time... for subtracting packet time */
#endif

        struct sockaddr_in *to = (struct sockaddr_in *) &whereto;
        int on = 1;
        int alloc_len;
        struct protoent *pe;
        int ttl, probe, i;
        int last_i;
        int last_ttl;
        int ttl_diff;
        int spr_ttl;
        int idx;                /* index to ttl based on spray sequence */
        int seq = 0;
        int tos = 0;
        struct hostent *hp;
        unsigned int lsrr = 0;
        u_long gw;
        u_char *oix;
#ifdef TEST                     /* For testing purposes.  This will one day */
        u_long gw_list[10];     /* be the list of intermediate gateways for */
#endif                          /* LSRR on netbsd kernels. */
        u_long curaddr;
        float min;
        float max;
        float sum;
        float sumsq;
        int cc;
        int probe_protocol=IPPROTO_UDP;         /* what IP protocol to use */
        struct timeval tv;
        struct timeval deadline;
        struct ip *ip;
#ifdef V630
	int hdrlen;	/* length of IP and protocol headers */
#endif

	/* cph 2000/10/15 - get raw sockets then drop priviledges ASAP */
	get_sockets();
#ifndef VMS
	if (setuid(getuid())) {
		perror("setuid");
		exit(errno);
	}
#endif /* VMS has its own protections for privileged programs */

	/* cph - end of additions */

        sprintf(terminator,"\n");       /* Standard line terminator */
        oix = optlist;
        bzero(optlist, sizeof(optlist));

#ifndef VMS_CLD
#ifdef __vms
        if (argc < 3) fixargs(&argc,argv,av);
#endif
        argc--, av++;
        while (argc && *av[0] == '-')  {
                while (*++av[0])
                        switch (*av[0]) {
                        case 'a':
                                automagic = 1;
                                break;
                        case 'U':
                                hurry_mode =1;
                                break;
                        case 'A':
                                as_lookup = 1;
                                break;
                        case 'd':
                                options |= TRT_DEBUG;
                                break;
                        case 'g':
                                argc--, AbortIfNull((++av)[0]);
                                if ((lsrr+1) >= ((MAX_IPOPTLEN-IPOPT_MINOFF)/sizeof(u_long))) {
                                  Fprintf(stderr,"No more than %d gateway%s",
                                          ((MAX_IPOPTLEN-IPOPT_MINOFF)/sizeof(u_long))-1,terminator);
                                  exit(1);
                                }
                                if (lsrr == 0) {
                                  *oix++ = IPOPT_LSRR;
                                  *oix++;       /* Fill in total length later */
                                  *oix++ = IPOPT_MINOFF; /* Pointer to LSRR addresses */
                                }
                                lsrr++;
                                if (*av[0] ==0) {
                                    Fprintf(stderr,"Hosts are not blank.%s",terminator);
                                    exit(1);
                                }
                                if (isdigit(*av[0])) {
                                  gw = inet_addr(*av);
                                  if (gw) {
                                    bcopy(&gw, oix, sizeof(u_long));
                                  } else {
                                    Fprintf(stderr, "Unknown host %s%s",av[0],terminator);
                                    exit(1);
                                  }
                                } else {
                                  hp = gethostbyname(av[0]);
                                  if (hp) {
                                    bcopy(hp->h_addr, oix, sizeof(u_long));
                                  } else {
                                    Fprintf(stderr, "Unknown host %s%s",av[0],terminator);
                                    exit(1);
                                  }
                                }
#ifdef TEST     /* store gateways for netbsd kernels */
                                bcopy(oix,&gw_list[lsrr],sizeof(u_long));
#endif
                                oix += sizeof(u_long);
                                goto nextarg;
                        case 'I':
                                argc--, AbortIfNull((++av)[0]);
				if (isdigit(*av[0])) {
                                probe_protocol = atoi(av[0]);
				} else {
					pe = getprotobyname(av[0]);
					if (!pe) {
						Fprintf(stderr, "unknown protocol %s%s",
							av[0], terminator);
						exit(1);
					}
					probe_protocol = pe->p_proto;
				}
                                if (probe_protocol > 254) {
                                        Fprintf(stderr, "protocol must be <=254%s",terminator);
                                        exit(1);
                                }
                                goto nextarg;
                        case 'S':
                                argc--, AbortIfNull((++av)[0]);
                                min_ttl = atoi(av[0]);
				if (min_ttl > max_ttl) {
					Fprintf(stderr, "min ttl must be <= max_ttl(%u)%s",max_ttl,terminator);
                                        exit(1);
                                }
				if (min_ttl >= SPRAYMAX) {
					Fprintf(stderr,"min ttl must be <%d%s",SPRAYMAX,terminator);
					exit(1);
				}
                                goto nextarg;
                        case 'm':
                                argc--, AbortIfNull((++av)[0]);
                                max_ttl = atoi(av[0]);
				if (max_ttl < min_ttl) {
					Fprintf(stderr,"max ttl must be >= min ttl(%u)%s",min_ttl,terminator);
                                        exit(1);
                                }
				if (max_ttl >=SPRAYMAX) {
					Fprintf(stderr, "max ttl must be <%d%s",SPRAYMAX,terminator);
					exit(1);
				}
                                goto nextarg;
                        case 'n':
                                nflag++;
                                break;
                        case 'O':
                                dns_owner_lookup = 1;
                                break;
                        case 'p':
                                argc--, AbortIfNull((++av)[0]);
                                port = atoi(av[0]);
                                if (port < 1) {
                                        Fprintf(stderr, "port must be >0%s",terminator);
                                        exit(1);
                                }
                                goto nextarg;
                        case 'P':
                                spray_mode = 1;
                                break;
                        case 'f':
                                argc--, AbortIfNull((++av)[0]);
                                sport = atoi(av[0]);
                                goto nextarg;
                        case 'q':
                                argc--, AbortIfNull((++av)[0]);
                                nprobes = atoi(av[0]);
				if ((nprobes < 1) || (nprobes >= SPRAYMAX)) {
					Fprintf(stderr,"nprobes must be >0 and <%lu%s",SPRAYMAX,terminator);
                                        exit(1);
                                }
                                goto nextarg;
                        case 'r':
                                options |= TRT_DONTROUTE;
                                break;
                        case 's':
                                /*
                                 * set the ip source address of the outbound
                                 * probe (e.g., on a multi-homed host).
                                 */
                                argc--, AbortIfNull((++av)[0]);
                                source = av[0];
                                goto nextarg;
                        case 't':
                                argc--, AbortIfNull((++av)[0]);
                                tos = atoi(av[0]);
                                if (tos < 0 || tos > 255) {
                                        Fprintf(stderr, "tos must be 0 to 255%s",terminator);
                                        exit(1);
                                }
                                goto nextarg;
                        case 'u':
                                utimers = 1;
                                break;
                        case 'v':
                                verbose++;
                                break;
                        case 'w':
                                argc--, AbortIfNull((++av)[0]);
                                waittime = atof(av[0]);
                                if (waittime <= .01) {
                                        Fprintf(stderr, "wait must be >10 msec%s",terminator);
                                        exit(1);
                                }
                                goto nextarg;
                        case 'M':
                                mtudisc++;
                                break;
                        case '$':
                                min_ttl = 64;
                                max_ttl = 64;
                                nprobes = 1;
                                pingmode = 1;
                                break;
                        case 'Q':
                                pploss = 1;
                                ppdelay = 0;
                                break;
                        case 'T':
                                av++;
                                if (--argc < 1) {
                                        Fprintf(stdout,usage,TR_VERSION);
                                        exit(1);
                                }
                                strncpy(terminator,av[0],TERM_SIZE);
                                terminator[TERM_SIZE -1] = 0;
                                goto nextarg;
                        default:
                                Fprintf(stdout,usage,TR_VERSION);
                                exit(1);
                        }
        nextarg:
                argc--, av++;
        }
#else /* VMS_CLD defined */
#include "clis.h"
#endif /* VMS_CLD */

        if (argc < 1)  {
                Fprintf(stdout,usage,TR_VERSION);
                exit(1);
        }
#ifndef vms
        setlinebuf (stdout);
#endif

        (void) bzero((char *)&whereto, sizeof(struct sockaddr));
        to->sin_family = AF_INET;
#ifdef VMS_CLD
        av[0] = hostname;
#endif
        to->sin_addr.s_addr = inet_addr(av[0]);
        if ((int)to->sin_addr.s_addr != -1) {
		(void) strncpy(hnamebuf, av[0], sizeof(hnamebuf));
		hnamebuf[sizeof(hnamebuf)-1] = 0;
                hostname = hnamebuf;
        } else {
                hp = gethostbyname(av[0]);
                if (hp) {
                        to->sin_family = hp->h_addrtype;
                        bcopy(hp->h_addr, (caddr_t)&to->sin_addr, hp->h_length);
                        hostname = hp->h_name;
                } else {
                        Fprintf(stderr,"%s: unknown host %s%s", argv[0], av[0],terminator);
                        exit(1);
                }
        }

#ifndef VMS_CLD
        if (argc >= 2)
                datalen = atoi(av[1]);
        if (datalen < 0 || datalen >= MAXPACKET) {
                Fprintf(stderr, "traceroute: packet size must be 0 <= s < %ld%s",
                        (long) MAXPACKET - sizeof(struct opacket),terminator);
                exit(1);
        }
#else /* VMS_CLD defined */
#include "clis.h"
#endif /* VMS_CLD */
        if (mtudisc)
          /*  Ignore data length as set.  Set it to a large value to
              start things off...  */
#ifndef MAX_DATALEN
  	  datalen = mtuvals[0];
#else
          datalen=MAX_DATALEN;
#endif
        if (datalen < (int) (sizeof(struct opacket) + MAX_IPOPTLEN)) {
          alloc_len = sizeof(struct opacket) + MAX_IPOPTLEN;
        } else {
          alloc_len = datalen;
        }
#ifdef V630
	/* Round up to even value for cksum() */
	alloc_len = (alloc_len + 1) & -2;
#endif

        if (spray_mode) {
           if (nprobes*max_ttl >= SPRAYMAX) {
              Fprintf(stderr,"Spray mode limited to %d packets.\n",SPRAYMAX);
              Fprintf(stderr,"Max TTL of %d with %d probes = %d\n",
                        max_ttl,nprobes,max_ttl*nprobes);
              Fprintf(stderr,"Disabling spray mode.\n");
              spray_mode = 0;
           }
           if (pploss) {
              Fprintf(stderr,"spray and packet stats are incompatible.\n");
              spray_mode = 0;
           }
           if (mtudisc) {
              Fprintf(stderr,"spray and MTU discovery are incompatible.\n");
              spray_mode = 0;
           }
           if (lsrr > 0) {
              Fprintf(stderr,"spray and loose source are incompatible.\n");
              spray_mode = 0;
           }
	   if (probe_protocol != IPPROTO_UDP) {
	      Fprintf(stderr,"spray mode requires UDP packets.  Disabled.\n");
	      spray_mode = 0;
	   }
        }

        outpacket = (struct opacket *)malloc((unsigned)alloc_len);

        if (! outpacket) {
                perror("traceroute: malloc");
                exit(1);
        }
        (void) bzero((char *)outpacket, alloc_len);
        outpacket->ip.ip_dst = to->sin_addr;
        outpacket->ip.ip_tos = tos;

        last_tos = tos;

        ident = (getpid() & 0xffff) | 0x8000;

        /*  ^C punts you to the next hop.  Twice will exit.  */

#ifndef __linux__
        NOERR(signal(SIGINT,halt),"signal SIGINT");
#endif /* __linux__ */

        if (lsrr > 0) {
          lsrr++;
          optlist[IPOPT_OLEN]=IPOPT_MINOFF-1+(lsrr*sizeof(u_long));
          bcopy((caddr_t)&to->sin_addr, oix, sizeof(u_long));
          oix += sizeof(u_long);
          while ((oix - optlist)&3) oix++;              /* Pad to an even boundry */
          _optlen = (oix - optlist);

          if ((pe = getprotobyname("ip")) == NULL) {
            perror("traceroute: unknown protocol ip");
            exit(10);
          }
#ifndef TEST
          if ((setsockopt(sndsock, pe->p_proto, IP_OPTIONS, optlist, oix-optlist)) < 0) {
            perror("traceroute: lsrr options");
            exit(5);
          }
#else /* TEST manual lsrr */
          Fprintf(stderr,"Current test IP header length: %d\n",outpacket->ip.ip_hl);
#endif
        }

#ifndef V630
        if (datalen < (int) (sizeof (struct opacket) + _optlen)) {
          /*  The chosen size is too small to fit everything...
              make it bigger:  */
          datalen = sizeof (struct opacket) + _optlen;
        }
#else
        hdrlen = (int) (sizeof (struct ip) + _optlen);
        switch (probe_protocol) {
                case IPPROTO_UDP:
                hdrlen += sizeof(struct udp_probe);
                break;

                case IPPROTO_ICMP:
                hdrlen += ICMP_MINLEN;
                break;

                default: { }  /* Braces good for some compiler versions */
        }

        if (datalen < hdrlen) {
           /*  The chosen size is too small to fit everything...
               make it bigger:  */
          datalen = hdrlen;
        }
#endif

#ifdef SO_SNDBUF
        if (setsockopt(sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&datalen,
                       sizeof(datalen)) < 0) {
                perror("traceroute: SO_SNDBUF");
                exit(6);
        }
#endif /* SO_SNDBUF */
#ifdef IP_HDRINCL
        if (setsockopt(sndsock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
                       sizeof(on)) < 0) {
                perror("traceroute: IP_HDRINCL");
                exit(6);
        }
#endif /* IP_HDRINCL */
        if (options & TRT_DEBUG)
                if (setsockopt(sndsock, SOL_SOCKET, SO_DEBUG,
                                  (char *)&on, sizeof(on))) {
			perror("traceroute: SO_DEBUG");
			exit(6);
		}
        if (options & TRT_DONTROUTE)
                if (setsockopt(sndsock, SOL_SOCKET, SO_DONTROUTE,
                                  (char *)&on, sizeof(on))) {
			perror("traceroute: SO_DONTROUTE");
			exit(6);
		}

        if (source) {
                (void) bzero((char *)&from, sizeof(struct sockaddr));
                from.sin_family = AF_INET;
                from.sin_addr.s_addr = inet_addr(source);
                if ((int)from.sin_addr.s_addr == -1) {
                        Fprintf(stderr,"traceroute: unknown host %s%s", source,terminator);
                        exit(1);
                }
                outpacket->ip.ip_src = from.sin_addr;
#ifndef IP_HDRINCL
                if (bind(sndsock, (struct sockaddr *)&from, sizeof(from)) < 0) {
                        perror ("traceroute: bind:");
                        exit (1);
                }
#endif /* IP_HDRINCL */
        }

        Fprintf(stderr, "traceroute to %s (%s)", hostname,
                inet_ntoa(to->sin_addr));
        if (source)
                Fprintf(stderr, " from %s", source);
	Fprintf(stderr, ", %d hops max", max_ttl);
	if (! mtudisc)
		Fprintf(stderr, ", %d byte packets", datalen);
	Fprintf(stderr,"%s", terminator);
        (void) fflush(stderr);

#ifdef TEST
        if (lsrr != 0) {
           for (ttl = 1; ttl < lsrr ; ++ttl) {
                Fprintf(stderr,"Lsrr hop %d is %s\n",ttl,inet_ntoa(gw_list[ttl]));
           }
        }
#endif
   if (!spray_mode) {
#ifdef V630
#ifndef SOLARIS
      /* Solaris is broken: sendto() with a large packet doesn't set the
       * return value and errno as sendto(3n) says it should.  It sends an
       * ICMP unreachable message to itself, though, so we'll pick that up
       * later.
       */
      if (mtudisc)
         /* Get interface MTU */
         send_probe(seq, -1, probe_protocol);
#endif /* SOLARIS */
#endif /* V630 */
      /* For all TTL do */
      consecutive = 0;
      for (ttl = min_ttl; ttl <= max_ttl; ++ttl) {
         bzero(&addr_last,sizeof(addr_last));
         got_there = unreachable = mtu = lost =0;
         min = max = sum = sumsq = 0.0;
         throughput = (double) 0.0;

         if (new_mtu != 0) {
            Fprintf(stdout,"MTU=%d\n",new_mtu);
            new_mtu=0;
         }
	 print_ttl(ttl);
         /* For all probes do */
         for (probe = 0; probe < nprobes; ++probe) {
            (void) gettimeofday(&tv, NULL);
            send_probe(++seq, ttl, probe_protocol);
            deadline.tv_sec = tv.tv_sec + (int) waittime;
            deadline.tv_usec=tv.tv_usec+((int) (waittime*1000000.0))%1000000;
            if (deadline.tv_usec >= 1000000) {
               deadline.tv_usec -= 1000000;
               deadline.tv_sec++;
            }
            /* Get an answer */
            while (cc = wait_for_reply(s, &from, &deadline)) {
               if ((i = packet_ok(packet, cc, &from, seq, probe_protocol))) {
                  float dt = deltaT(&tv);
                  if (sum == 0) {
                     sum = min = max = dt;
                     sumsq = dt*dt;
                  } else {
                     if (dt < min) min = dt;
                     if (dt > max) max = dt;
                     sum += dt;
                     sumsq += dt*dt;
                  }
                  if (hurry_mode) probe = nprobes;

                  print_from(&from);
		  
                  if (i == -1) { /* ICMP_XCEED */
                     decode_icmp_ext(packet, cc);
                  }

                  if (ppdelay) {
                     print_time(&dt);
                  }

                  print_packet((struct ip *) &packet, i);

                  consecutive = 0; /* got a packet back! */
                  break;
               } /* end if packet ok */
            } /* end while */

               if (cc == 0) {
                  if (pingmode) exit(23);
                  Fprintf(stdout," *");
                  (void) fflush(stdout);

                  lost++;
                 
#ifndef __linux__ 
		  /*  Reset the ^C action from exit to skip TTL  */
                  if (haltf==0 && lost==1)
                  
		  NOERR(signal(SIGINT,halt), "signal SIGINT");
                  /* we've missed at least one packet, so let's check for the
                     signal to go to the next ttl */
                  if (haltf > 0) {
                     haltf = 0;
                     consecutive = 0;
                     break;
                  }
#endif /* __linux__ */
               } /* end if cc = 0 */
         } /* end for probe */

         if (pploss) {
            if (lost < probe) {
               throughput = ( 100.0 - ( ( lost * 100.0 ) / probe ));
               Fprintf(stdout,
                       "  (%1.1f ms/%1.1f ms(+-%1.1f ms)/%1.1f ms)",
                       min, (sum / (probe - lost)),
                       (float)sqrt((double)sumsq)/(probe-lost), max);
               Fprintf(stdout," %d/%d (%#3.2f%%)", (probe - lost),
                       probe, throughput);
               (void) fflush(stdout);
            }
         }
#ifndef FIXT
         Fprintf(stdout,terminator);
#else /* FIXT */
         Fprintf(stdout,"%s",terminator);
#endif /* FIXT */
         /* If we're running one probe and we get back one packet, that's
            no excuse to quit unless we're really done! */
#ifdef V630
         if ( got_there || (hurry_mode && unreachable) ||
#ifndef CISCO_ICMP
               unreachable >= nprobes
            ) 
#else /* CISCO_ICMP meaning not all our packets will be returned. */
               ( (unreachable+lost >= nprobes ) && unreachable )
            ) 
#endif /* CISCO_ICMP */
#else /* !V630 */
         if ( ((nprobes == 1) && (got_there || unreachable)) ||
#ifndef CISCO_ICMP
               (got_there || unreachable > nprobes - 1) )
#else /* CISCO_ICMP meaning not all our packets will be returned. */
               (got_there || unreachable > nprobes - 1) ||
               ( (unreachable+lost > nprobes - 1) && (unreachable > 0) ))
#endif /* CISCO_ICMP */
#endif /* V630 */ 
           exit(0);
         if (new_mtu != 0) {
            ttl--;  /*  Redo the same TTL  */
            datalen = new_mtu;  /*  Set the new data length  */
         }
         if (automagic && (consecutive++ > 9)) break;
      } /* end for TTL */

/* end non-spray mode */

} else {

/*
 * Enter Spray mode
 */
   spray_target = spray_max = spray_total = 0;
   spray_min = SPRAYMAX+1;

   /* For all TTL do */
   for (ttl = min_ttl; ttl <= max_ttl; ++ttl) {
      spray_rtn[ttl] = (unsigned int *)malloc(sizeof(int)*nprobes + 1);
      for (probe = 0; probe < nprobes; ++probe) {
             spray_rtn[ttl][probe]=0;
         send_probe(++seq, ttl, probe_protocol);
      }
   }
   (void) gettimeofday(&tv, NULL);
   deadline.tv_sec = tv.tv_sec + (int) waittime;
   deadline.tv_usec=tv.tv_usec+((int) (waittime*1000000.0))%1000000;
   if (deadline.tv_usec >= 1000000) {
      deadline.tv_usec -= 1000000;
      deadline.tv_sec++;
   }
   /* Go get responses until either we get them all, or timeout */
   while (  ((((int)pow(2,spray_min)-1)&response_mask) != ((int)pow(2,spray_min)-2)) &&
            (cc = wait_for_reply(s,&from,&deadline))  ) {
      (void) packet_ok(packet, cc, &from, seq, probe_protocol);
   }

   last_i = 1;
   last_ttl = 0;
   bzero(&addr_last, sizeof(addr_last));
   for (i = min_ttl; i <= max_ttl; i++) {
      /* First see if it's valid, and if so play with its time */
      idx = spray_rtn[i][0];
      if ((idx > 0) && (idx < SPRAYMAX) && (spray[idx].from.sin_addr.s_addr != 0)) {
              spr_ttl = spray[idx].ttl;
              if (spr_ttl != i) {
                  Fprintf(stderr,"Check failure spray(rtn[i]) !=i\n");
                  exit(0);
              }

          /* do not display duplicate entries (responses beyond terminus from same host) */
              if (0 != memcmp( &spray[idx].from.sin_addr.s_addr,
                          &addr_last.sin_addr.s_addr,
                                  sizeof(addr_last.sin_addr.s_addr) )) {

                 ttl_diff = (spr_ttl - last_ttl);
                 if (ttl_diff > 1) {
                   for (last_i = last_ttl+1; last_i < spr_ttl; last_i++) {
                       print_ttl(last_i);
                       for (probe = 1; probe <= nprobes ; probe++) {
                          Fprintf(stdout," *");
                       } /* end for probes */
#ifndef FIXT
                       Fprintf(stdout,terminator);
#else /* FIXT */
                       Fprintf(stdout,"%s",terminator);
#endif /* FIXT */
                   } /* end for last i */
                 } /* endf if spr_ttl ... */

             if (spr_ttl > last_ttl) {
                print_ttl(spr_ttl);
                last_ttl = spr_ttl;
             }

             print_from(&spray[idx].from);

             for (probe = 0; probe < nprobes; ++probe) {
                     if (spray_rtn[i][probe] != 0) {
                     tvsub(&spray[spray_rtn[i][probe]].rtn,&spray[spray_rtn[i][probe]].out);
                     ddt=spray[spray_rtn[i][probe]].rtn.tv_sec*1000.0+
                        ((float)spray[spray_rtn[i][probe]].rtn.tv_usec)/1000.0;
                     print_time(&ddt);
                         } else {
                             Fprintf(stdout," *");
                         }
             }
#ifndef FIXT
             Fprintf(stdout,terminator);
#else /* FIXT */
             Fprintf(stdout,"%s",terminator);
#endif /* FIXT */
                 } /* no duplicate entries */
      } /* end if nonzero type */
   } /* end for */
} /* end spray mode */
}

void print_packet(struct ip *ip, int i)
{
#ifdef TRACE_TOS
{
  struct icmp *icp = (struct icmp *) (((u_char *)ip)+(ip->ip_hl<<2));
  struct ip *inner_ip = (struct ip *) (((u_char *)icp)+8);
  int tos = inner_ip->ip_tos;

  if (tos != last_tos)
    {
      Fprintf (stdout," (TOS=%d!)",tos);
    }
  last_tos = tos;
}
#endif /* TRACE_TOS */
                    switch(i - 1) {
                        case 13:
                                Fprintf(stdout," !A"); /* admin prohibited*/
                                ++unreachable;
                                break;
                        case ICMP_UNREACH_PORT:
#ifndef ARCHAIC
                                ip = (struct ip *)packet;
                                if (ip->ip_ttl <= 1)
                                Fprintf(stdout," !");
#endif /* ARCHAIC */
                                ++got_there;
                                break;
                        case ICMP_UNREACH_NET:
                                ++unreachable;
                                Fprintf(stdout," !N");
                                break;
                        case ICMP_UNREACH_HOST:
                                ++unreachable;
                                Fprintf(stdout," !H");
                                break;
                        case ICMP_UNREACH_PROTOCOL:
                                ++got_there;
                                Fprintf(stdout," !P");
                                break;
                        case ICMP_UNREACH_NEEDFRAG:
                                if (mtudisc) {
                                   /* Doing MTU discovery */
                                   mtu = (ntohl(icp->icmp_void) & 0xffff);
                                   if (mtu >= datalen) {
                                    /*  This should never happen.  There is
                                        a serious bug somewhere... */
                                      Fprintf (stdout," !M>");
                                   } else if (mtu == 0) {
				    /*  Looks like router is not RFC1191 -
 					compliant (using original RFC 792
					spec). */
				      new_mtu = reduce_mtu(datalen);
				      Fprintf(stdout," !M?%d", new_mtu);
                                   } else {
                                      new_mtu = mtu;
                                      Fprintf (stdout," !M=%d", new_mtu);
                                   }
                                   break;
                                } else {
                                  /* Not doing MTU discovery */
                                  ++unreachable;
                                  Fprintf(stdout," !F");
                                  break;
                                }
                        case ICMP_UNREACH_SRCFAIL:
                                ++unreachable;
                                Fprintf(stdout," !S");
                                break;
                    } /* end switch */
}

void print_time(float *dt)
{
   if (utimers) {
      Fprintf(stdout,"  %3.3f ms", *dt);
   } else {
      Fprintf(stdout,"  %d ms", (int) (*(dt)+0.5));
   }
   (void) fflush(stdout);
}

void print_ttl(int ttl)
{
   Fprintf(stdout,"%2d ", ttl);
   (void)fflush(stdout);
}

wait_for_reply(sock, from, deadline)
        int sock;
        struct sockaddr_in *from;
        struct timeval     *deadline;
{
        fd_set fds;
        struct timeval wait;
        struct timeval now;
        int cc = 0;
        int fromlen = sizeof (*from);

#ifndef __linux__
        gettimeofday(&now, NULL);
#else /* __linux__ */
        gettimeofday(&now, &tz);
#endif /* __linux__ */
        if ((now.tv_sec > deadline->tv_sec) ||
            ( (now.tv_sec == deadline->tv_sec) &&
             (now.tv_usec > deadline->tv_usec) )  ) return (int)NULL;

        wait.tv_sec= deadline->tv_sec- now.tv_sec;
        if (deadline->tv_usec >= now.tv_usec) {
          wait.tv_usec= deadline->tv_usec- now.tv_usec;
        } else {
          wait.tv_usec= (1000000 - now.tv_usec)+ deadline->tv_usec;
          wait.tv_sec--;
        }

        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        if (select(sock+1, &fds, (fd_set *)0, (fd_set *)0, &wait) > 0)
                cc=recvfrom(s, (char *)packet, sizeof(packet), 0,
                            (struct sockaddr *)from, &fromlen);
        return((int)cc);
}

send_probe(seq, ttl, proto)
int ttl;
int seq;
int proto;
{
        struct opacket *op = outpacket;
        struct ip *ip = &op->ip;
#ifndef V630
        struct udphdr *up = &op->udp;
#else
 	struct udphdr *up;
	struct icmp *icmpp;
#endif
        int i;
	int mtu_low, mtu_high;

#ifdef BROKEN_RAWIP
 	register char *cp, *dp;
	static char *np = 0;
	int raw_optlen = _optlen;
	char raw_optlist[sizeof(optlist)];
#endif /* BROKEN_RAWIP */

#ifdef V630
        if (ttl == -1) {
           /* Getting interface MTU for path MTU discovery */
           mtu_low = mtuvals[(sizeof(mtuvals)/sizeof(mtuvals[0]))-1-1];
           mtu_high = datalen;
           datalen = (mtu_low + mtu_high) >> 1;
        }
#endif

      retry:


      /* W. Richard Stevens: UNIX Network Programming, Volume 1,
       * Second Edition, p. 657:
       *
       * "Unfortunately the IP_HDRINCL socket option has never been
       *  documented, specifically with regard to the byte ordering of
       *  the fields in the IP header.  On Berkeley-derived kernels all
       *  fields are in network byte order except ip_len and ip_off,
       *  which are in host byte order (pp. 233 and 1057 of TCPv2).  On
       *  Linux, however, all the fields must be in network byte order."
       *
       * See http://www.leto.net/docs/libnet-precis.txt and
       * doc/RAWSOCKET_NON_SEQUITUR in libnet distribution
       * (http://www.packetfactory.net/libnet) for more details.
       *
       * Linux ignores ip_len and fills it in itself from the sendto()
       * length.
       */


        if (mtudisc) {
#ifndef BYTESWAP_IP_FLAGS
          ip->ip_off = (u_short) IP_DF;
#else /* BYTESWAP_IF_FLAGS */
	  ip->ip_off = htons((u_short) IP_DF);
#endif
        }
        else {
          ip->ip_off = 0;
        }

        ip->ip_p = proto;

#ifdef BROKEN_RAWIP
	ip->ip_len = (u_short)datalen; /* OS ignores setsockopt() */
#else /* ! BROKEN_RAWIP */

#ifndef BYTESWAP_IP_LEN
        ip->ip_len = ((u_short)datalen-_optlen);   /*  The OS inserts options  */
#else /* BYTESWAP_IP_LEN */
        ip->ip_len = htons((u_short)datalen-_optlen);   /*  The OS inserts options  */
#endif /* BYTESWAP_IP_LEN */
#endif /* ! BROKEN_RAWIP */

#ifdef V630
	if (ttl == -1)
	   ip->ip_ttl = 0;
	else
#endif
	ip->ip_ttl = ttl;
        ip->ip_v = IP_VERSION;
        ip->ip_hl = sizeof(*ip) >> 2;

        if (proto == IPPROTO_UDP) {
#ifdef V630
                up = &op->ip_payload.udp_probe.udp;
#endif
                up->uh_sport = htons(ident);
                up->uh_dport = htons(port+seq);
                up->uh_ulen = htons((u_short)(datalen - sizeof(struct ip) - _optlen));
#ifndef V630
                up->uh_sum = 0;
        }

        op->seq = seq;
        op->ttl = ttl;
#else
                op->ip_payload.udp_probe.seq = seq;
                op->ip_payload.udp_probe.ttl = ttl;
#endif

#ifndef V630
#ifndef __linux__
        (void) gettimeofday(&op->tv, NULL);
#else /* __linux__ */
        (void) gettimeofday(&op->tv, &tz);
#endif /* __linux__ */

#else /* V6.3.0: */
#ifndef __linux__
                (void) gettimeofday(&op->ip_payload.udp_probe.tv, NULL);
#else /* __linux__ */
                (void) gettimeofday(&op->ip_payload.udp_probe.tv, &tz);
#endif /* __linux__ */
        } else if (proto == IPPROTO_ICMP) {
                icmpp = &op->ip_payload.icmp_probe;
                icmpp->icmp_type = ICMP_ECHO;
                icmpp->icmp_hun.ih_idseq.icd_id = ident;
                icmpp->icmp_hun.ih_idseq.icd_seq = seq;
                /* Unlike UDP, we need a correct checksum. */
                cksum((u_int16_t *)icmpp,
                        (datalen - sizeof(struct ip) - _optlen + 1) >> 1,
                        &icmpp->icmp_cksum);
        }
#endif 

#ifdef BROKEN_RAWIP
      if (!np)
              np = (char *)malloc(datalen);
      bzero(np, datalen);
      bzero(raw_optlist, sizeof raw_optlist);

      dp = np;
      if (_optlen)
              {
              raw_optlen = _optlen - sizeof (struct in_addr);
              raw_optlist[IPOPT_OPTVAL] = optlist[IPOPT_OPTVAL];
              raw_optlist[IPOPT_OLEN] = optlist[IPOPT_OLEN] -
                                              sizeof (struct in_addr);
              raw_optlist[IPOPT_OFFSET] = optlist[IPOPT_OFFSET];
              bcopy(&optlist[IPOPT_OFFSET + 1], &ip->ip_dst,
                              sizeof (struct in_addr));
              bcopy(&optlist[IPOPT_OFFSET + 1] + sizeof (struct in_addr),
                      &raw_optlist[IPOPT_OFFSET + 1],
                      raw_optlen - sizeof (struct in_addr));
              ip->ip_hl = (sizeof(*ip) + raw_optlen) >> 2;
              for     (cp = (char *)ip, i = sizeof (*ip); i; i--)
                      *dp++ = *cp++;
              for     (cp = (char *)raw_optlist, i = raw_optlen; i; i--)
                      *dp++ = *cp++;
              }
      else
              for     (cp = (char *)ip, i = sizeof (*ip); i; i--)
                      *dp++ = *cp++;
      for     (cp = (char *)up, i = sizeof (*up); i; i--)
              *dp++ = *cp++;
      *dp++ = seq;
      *dp++ = ttl;
      bcopy(&op->ip_payload.udp_probe.tv, dp, sizeof (op->ip_payload.udp_probe.tv));

#ifdef SPRAY
      if (spray_mode) {
           if (proto == IPPROTO_UDP) spray[seq].dport = up->uh_dport;
           spray[seq].ttl   = ttl;
           bcopy(&op->ip_payload.udp_probe.tv, &spray[seq].out, sizeof(struct timeval));
      }
#endif

      i = sendto(sndsock, (char *)np, datalen, 0, &whereto,
                 sizeof(struct sockaddr));

      if (i < 0 || i != datalen)  {
#else


#ifdef SPRAY
        if (spray_mode) {
#ifndef V630
           if (proto == IPPROTO_UDP) spray[seq].dport = up->uh_dport;
#else /* V630 */
           /* Must be IPPROTO_UDP */
           spray[seq].dport = up->uh_dport;
#endif /* V630 */
           spray[seq].ttl   = ttl;

#ifndef V630
           bcopy(&op->tv, &spray[seq].out, sizeof(struct timeval));
#else /* V630 */
           bcopy(&op->ip_payload.udp_probe.tv, &spray[seq].out, sizeof(struct timeval));
#endif /* V630 */
        }
#endif /* SPRAY */

        i = sendto(sndsock, (char *)outpacket, datalen - _optlen, 0, &whereto,
                   sizeof(struct sockaddr));

        if (i < 0 || i != datalen - _optlen)  {
#endif /* ! BROKEN_RAWIP */

                if (i<0) {
                    if (errno == EMSGSIZE) {
#ifdef V630
		        if (ttl == -1) 
 		        mtu_high = datalen -1;
		    else {
#endif /* V630 */
		        datalen = reduce_mtu(datalen);
		        Fprintf(stdout," MTU=%d",datalen);
			goto retry;
#ifdef V630 

                    }
#endif
                }
                else
                    perror("sendto");
#ifdef V630
              } else {
#else /* ! V630 */
              }
#endif
		Fprintf(stderr,"traceroute: wrote %s %d chars, ret=%d%s",
	   	   hostname, datalen, i, terminator);
		(void) fflush(stdout);

#ifdef V630
                }
        } else if (ttl == -1)
            mtu_low = datalen;
        if (ttl == -1) {
            if (mtu_high > mtu_low) {
                if (mtu_high == mtu_low + 1)
                    datalen = mtu_high;
                else
                    datalen = (mtu_high + mtu_low) >> 1;
                goto retry;
            } else if (mtu_high < mtu_low) {
                /* Should never happen */
                Fprintf(stderr,"traceroute: unable to determine interface MTU");
                exit(1);
            }
            /* else mtu_high == mtu_low and we have interface MTU */
            new_mtu = datalen = mtu_high;
#endif /* V630 */

        }
}
  
void
cksum(buf, nwords, ckaddr)
        u_int16_t          *buf;
        int                nwords;
        volatile u_int16_t *ckaddr;
{
        /* Based on cksum in Douglas E. Comer and David L. Stevens:
         * Internetworking with TCP/IP Volume II.  We store the checksum
         * ourselves instead of returning its value to prevent the 
         * compiler possibly optimising away its initialisation.
         *
         * If the size in bytes of the buffer is odd, nwords (the size in
         * 16-bit words) should be rounded up and the byte beyond the end of
         * the buffer should be zero.
        */

        u_int32_t sum;

        *ckaddr = 0;

        for (sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum & 0xffff);    /* add in carry   */
        sum += (sum >> 16);                    /* maybe one more */
        *ckaddr = ~sum;
}


float deltaT(tp)
        struct timeval *tp;
{
        struct timeval tv;

#ifndef __linux__
        (void) gettimeofday(&tv, NULL);
#else /* __linux__ */
        (void) gettimeofday(&tv, &tz);
#endif /* __linux__ */
        tvsub(&tv, tp);
        return (tv.tv_sec*1000.0 + ((float)tv.tv_usec)/1000.0);
}

/*
 * Convert an ICMP "type" field to a printable string.
 */
char *
pr_type(t)
        u_char t;
{
        static char *ttab[] = {
        "Echo Reply",   "ICMP 1",       "ICMP 2",       "Dest Unreachable",
        "Source Quench", "Redirect",    "ICMP 6",       "ICMP 7",
        "Echo",         "ICMP 9",       "ICMP 10",      "Time Exceeded",
        "Param Problem", "Timestamp",   "Timestamp Reply", "Info Request",
        "Info Reply"
        };

        if(t > 16)
                return("OUT-OF-RANGE");

        return(ttab[t]);
}

/*
 *  Decodes ICMP extension header.
 *  draft-ietf-mpls-icmp-02.txt
 *  Jorge Boncompte - DTI2
 */
void decode_icmp_ext(buf, cc)
	u_char *buf;
	int cc;
{
	static unsigned long last_mpls_label;
	static unsigned int last_mpls_exp;
	unsigned long mpls_label;
	unsigned int ext_ver, ext_res, ext_chk, obj_hdr_len, mpls_exp;
	u_char 	obj_hdr_class, obj_hdr_type;

	/* IP hdr + ICMP hdr + 128b original packet + 4 bytes ICMP ext hdr */
	if (cc > 160) {
	    ext_ver = buf[156]>>4;
	    ext_res = (buf[156]&15)+ buf[157];
	    ext_chk = ((unsigned int)buf[158]<<8)+buf[159];

	    if (ext_ver == 2 && ext_res == 0 && ext_chk != 0) {
		/* Ok. This is an ICMP ext header. But we haven't checked
		    that the checksum is correct */ 
		obj_hdr_len = ((int)buf[160]<<8)+buf[161];
		obj_hdr_class = buf[162];
		obj_hdr_type = buf[163];

		if (obj_hdr_len >= 8 && obj_hdr_class == 1 && obj_hdr_type == 1) {
		    mpls_label = ((unsigned long)buf[164]<<12) +
                         ((unsigned int)buf[165]<<4) + ((buf[166]>>4) & 0xff); 
                    mpls_exp = (buf[166] >> 1) & 0x7;

		    /* Print the label, if it is different that the one
		       received with the last probe, print again. Maybe
		       in between the 2 probes happened a reroute? */
		    if (mpls_label != last_mpls_label ||
			mpls_exp != last_mpls_exp) {
			    last_mpls_label = mpls_label;
			    last_mpls_exp = mpls_exp;
			    Fprintf(stdout, " [MPLS: Label %lu Exp %u]",
				mpls_label, mpls_exp);
		    }
		}

		/* FIXME: We only print the first label */
		if (obj_hdr_len >= 12)
		    Fprintf(stdout, " More labels");
	    }
#if 0
	Fprintf(stdout, "\nICMP ext hdr Version %u Reserved %u Checksum %u\n",
    		ext_ver, ext_res, ext_chk);
	Fprintf(stdout, "Object header: lenght %u Class-Num %u Class-Type %u\n",
		obj_hdr_len, obj_hdr_class, obj_hdr_type);
#endif
	}
}

/*
 * packet_ok - Make sure it's a real ICMP return of a real packet
 */
packet_ok(buf, cc, from, seq, proto)
        u_char *buf;
        int cc;
        struct sockaddr_in *from;
        int seq;
        int proto;
{
        u_char type, code;
        int hlen, mtu;
        u_short temp;
        int tmp,tmp2;
        int spr_seq;
        int spr_ttl;
        int probecnt;

#ifndef ARCHAIC
        struct ip *ip;

        ip = (struct ip *) buf;
        /* get header length and convert from longwords to bytes */
        if ((ip->ip_v) != IP_VERSION) {
                Fprintf(stderr,"packet version not 4: %d%s",ip->ip_v,terminator);
                return (0);
        }
        hlen = ip->ip_hl <<2 ;
        if (cc < hlen + ICMP_MINLEN) {
                if (verbose)
                        Fprintf(stderr,"packet too short (%d bytes) from %s%s", cc,
                                inet_ntoa(from->sin_addr),terminator);
                return (0);
        }
        /* go from returned length of packet to cc=data portion */
        cc -= hlen;
        /* make icp point to supposed ICMP portion */
        icp = (struct icmp *) ((u_char *)buf+hlen);
#else
        icp = (struct icmp *)buf;
#endif /* ARCHAIC */
        type = icp->icmp_type; code = icp->icmp_code;
        if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
            type == ICMP_UNREACH) {
                struct ip *hip;
                struct udphdr *up = NULL;
                struct icmp *icp2 = NULL;

                hip = &icp->icmp_ip;
                hlen = hip->ip_hl << 2;
		if (proto == IPPROTO_UDP)
		   up = (struct udphdr *)((u_char *)hip + hlen);
		else if (proto == IPPROTO_ICMP)
		   icp2 = (struct icmp *)((u_char *)hip + hlen);
#ifdef SPRAY
/*
 * First we make sure we got a legal response back, and if so we
 * get the sequence number and ttl out of it
 */
                if (spray_mode) {
		   if (up == NULL) {
			   Fprintf(stderr,"invalid NULL UDP header%s", terminator);
			   return (0);
		   }
                   spr_seq = ntohs(up->uh_dport)-port;
                   if ( (spr_seq >=0) && (spr_seq < max_ttl*nprobes+1) ) {
                      spr_ttl = spray[spr_seq].ttl;
                                          response_mask |= (1 << spr_ttl);
/*
 * Now we increment the response count for this ttl, and then if it's the
 * first, increment the total of ttl's seen
 */
                      if (spray_rtn[spr_ttl][0] == 0) {
                        spray_total++;
                      }

              for (probecnt = 0; probecnt < nprobes; ++probecnt) {
                          if (spray_rtn[spr_ttl][probecnt] == 0) {
                                      spray_rtn[spr_ttl][probecnt] = spr_seq;
                                          break;
                                  }
                          }
/*
 * We want to do some heuristics on the smallest TTL received from the target
 * host, but we need the type for that...
 */
                spray[spr_seq].type = type;
                if (type == ICMP_UNREACH_PORT) {
                            if (spr_ttl < spray_min)  {
                                    spray_min = spr_ttl;
                                    }
                                spray_target = spr_ttl;
                        }
/*
 * We also want the largest TTL we've seen...
 */
                      if (spr_ttl > spray_max)
                         spray_max = spr_ttl;
/*
 * And finally, fill the data structure with the other things we'll need
 * to spit out later, namely the packet transit type and the source IP.
 */
                      gettimeofday(&(spray[spr_seq].rtn),0);
                      bcopy(&from->sin_addr,
                            &spray[spr_seq].from.sin_addr,
                            sizeof(from->sin_addr));

                   } /* end if sequence number valid */
                } /*end if spray mode */
#endif
		if (hlen + 12 <= cc && hip->ip_p == proto &&
		   hip->ip_ttl > 0) {
                 if (proto == IPPROTO_UDP) {
                    if (up->uh_sport == htons(ident) &&
                    up->uh_dport == htons(port+seq))
                        return (type == ICMP_TIMXCEED? -1 : code+1);
		 } else if (proto == IPPROTO_ICMP) {
		    if (icp2->icmp_hun.ih_idseq.icd_id == ident &&
		     icp2->icmp_hun.ih_idseq.icd_seq == seq)
			return (type == ICMP_TIMXCEED ? -1 : code+1);
                 } else {
		 /* XXX More than one trace at a time will be confusing */
                        return (type == ICMP_TIMXCEED? -1 : code+1);
                 }
               }
#ifdef V630
        } else if (type == ICMP_ECHOREPLY && code == 0) {
          if (proto == IPPROTO_ICMP                       &&
                  icp->icmp_hun.ih_idseq.icd_id  == ident &&
                  icp->icmp_hun.ih_idseq.icd_seq == seq)
                  return(ICMP_UNREACH_PORT+1);
#endif
        } /* end if valid ICMP type */

#ifndef ARCHAIC
        if (verbose) {
                int i;
                u_long *lp = (u_long *)&icp->icmp_ip;

                Fprintf(stderr,"\n%d bytes from %s to %s", cc,
                        inet_ntoa(from->sin_addr), inet_ntoa(ip->ip_dst));
                Fprintf(stderr,": icmp type %d (%s) code %d%s", type, pr_type(type),
                       icp->icmp_code,terminator);
                for (i = 4; i < cc ; i += sizeof(long))
                        Fprintf(stderr,"%2d: x%8.8lx\n", i, *lp++);
        }
#endif /* ARCHAIC */
        return(0);
}

int reduce_mtu(value)
int value;
{
  int i=0;

  while (value <= mtuvals[i]) i++;
  if (mtuvals[i] > 0) {
    value = mtuvals[i];
  }
  else {
    Fprintf (stderr," No valid MTU!!!%s",terminator);
    exit (1);
  }
  return (value);
}

char *lookup_owner();
char *doresolve ();
char *lookup_as();

void print_from(struct sockaddr_in *from)
{
   if (0 != memcmp( &from->sin_addr.s_addr,
                    &addr_last.sin_addr.s_addr,
                    sizeof(addr_last.sin_addr.s_addr) )) {
      if (nflag)
         Fprintf(stdout, " %s", inet_ntoa(from->sin_addr));
      else
         Fprintf(stdout, " %s (%s)", inetname(from->sin_addr),
                 inet_ntoa(from->sin_addr));

      if (as_lookup)
         Fprintf(stdout," [%s]", lookup_as(from->sin_addr));

      if (dns_owner_lookup)
         Fprintf(stdout," %s", lookup_owner(from->sin_addr));

      memcpy(&addr_last.sin_addr.s_addr,
             &from->sin_addr.s_addr,
             sizeof(addr_last.sin_addr.s_addr));
      }

}

print(buf, cc, from)
        u_char *buf;
        int cc;
        struct sockaddr_in *from;
{
        struct ip *ip;
        int hlen;

        ip = (struct ip *) buf;
        hlen = ip->ip_hl << 2;
        cc -= hlen;

        if (nflag)
                Fprintf(stdout, " %s", inet_ntoa(from->sin_addr));
        else
                Fprintf(stdout, " %s (%s)", inetname(from->sin_addr),
                       inet_ntoa(from->sin_addr));

        if (as_lookup)
          Fprintf(stdout," [%s]", lookup_as(from->sin_addr));

        if (dns_owner_lookup)
          Fprintf(stdout," %s", lookup_owner(from->sin_addr));

        if (verbose)
          Fprintf (stderr," %d bytes to %s", cc, inet_ntoa (ip->ip_dst));
      }

/*
 * Subtract 2 timeval structs:  out = out - in.
 * Out is assumed to be >= in.
 */
tvsub(out, in)
     register struct timeval *out, *in;
{
  if ((out->tv_usec -= in->tv_usec) < 0)   {
    out->tv_sec--;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

/*
 * Construct an Internet address representation.
 * If the nflag has been supplied, give
 * numeric value, otherwise try for symbolic name.
 */
char *
inetname(in)
     struct in_addr in;
{
  register char *cp;
  static char line[50];
  struct hostent *hp;
  static char domain[MAXHOSTNAMELEN + 1];
  static int first = 1;

  if (first && !nflag) {
    first = 0;
    /* Under certain conditions, gethostname returns a string that is
     * not NUL-terminated. Make sure there's a guard in place. */
    domain[sizeof(domain)-1] = 0;
    if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
        (cp = index(domain, '.')))
      (void) strcpy(domain, cp + 1);
    else
      domain[0] = 0;
  }
  cp = 0;
  if (!nflag && in.s_addr != INADDR_ANY) {
    hp = gethostbyaddr((char *)&in, sizeof (in), AF_INET);
    if (hp) {
      if ((cp = index(hp->h_name, '.')) &&
          !strcmp(cp + 1, domain))
        *cp = 0;
      cp = hp->h_name;
    }
  }
  if (cp) {
	  (void) strncpy(line, cp, sizeof(line));
	  line[sizeof(line)-1] = 0;
  } else {

    in.s_addr = ntohl(in.s_addr);
#define C(x)    ((x) & 0xff)
#ifndef __linux__
    sprintf(line, "%lu.%lu.%lu.%lu", C(in.s_addr >> 24),
#else /* __linux__ */
    sprintf(line, "%u.%u.%u.%u", C(in.s_addr >> 24),    /* Why no lu??? */
#endif /* __linux__ */

            C(in.s_addr >> 16), C(in.s_addr >> 8), C(in.s_addr));
  }
  return (line);
}

#ifdef V630
#ifndef __linux__
void halt()
{
  haltf++;

  NOERR(signal(SIGINT,0), "signal SIGINT,0");

}
#endif /* __linux__ */
#endif

/*
 *  Lookup owner of the net in DNS.
 */

char *lookup_owner(in)
     struct in_addr in;
{
  char dns_query[100];
  char *owner, *dot_ptr;
  unsigned char *addr_ptr;

  addr_ptr = (unsigned char *) (&in.s_addr);

  /* Try /24 */
  sprintf (dns_query, "%d.%d.%d.in-addr.arpa", addr_ptr[2], addr_ptr[1], addr_ptr[0]);
  if (!(owner = doresolve(dns_query))) {
    /* Failed, try /16 */
    sprintf (dns_query, "%d.%d.in-addr.arpa", addr_ptr[1], addr_ptr[0]);
    if (!(owner = doresolve(dns_query))) {
    /* Failed.  If eligible try /8 */
       if (addr_ptr[0] < 128) {
          sprintf (dns_query, "%d.in-addr.arpa", addr_ptr[0]);
          owner = doresolve(dns_query);
       } /* tried /8 for A's */
    } /* tried /16 */
  } /* tried /24 */

  /*  reformat slightly  */
  if (owner == NULL) {
     owner = NO_SOA_RECORD;
  } else {
    dot_ptr = (char *)strchr (owner, (int)'.');
    if (dot_ptr != NULL)
      *dot_ptr = '@';

    if (strlen(owner) > 0) {
      dot_ptr=owner + strlen (owner) - 1;
      while (*dot_ptr == ' ' || *dot_ptr == '.' ) {
        *dot_ptr = 0;
        dot_ptr--;
      }
    }
  }

  return (owner);

}

/*
 *  Lookup origin of the net in radb.
 */

char *lookup_as(in)
struct in_addr in;
{
  static char query[100];
  static unsigned char *addr_ptr;
  static char *sp;
  char *get_origin();

  addr_ptr = (unsigned char *) (&in.s_addr);

#ifdef FORCE_NATURAL_MASK
  if (addr_ptr[0] >= 192) {
    sprintf (query, "%d.%d.%d.0",addr_ptr[0],addr_ptr[1],addr_ptr[2]);
  } else if (addr_ptr[0] >= 128) {
    sprintf (query, "%d.%d.0.0",addr_ptr[0],addr_ptr[1]);
  } else {
    sprintf (query, "%d.0.0.0",addr_ptr[0]);
  }
#else
  sprintf (query,"%d.%d.%d.%d",addr_ptr[0],addr_ptr[1],addr_ptr[2],addr_ptr[3]);
#endif /* FORCE_NATURAL_MASK */

  sp = get_origin(query);
/*  printf("as_lookup: get_origin returned %d\n",sp); */
  if (0==sp) {
     return((char *)&nullstring);
  } else {
     return(sp);
  }

}

/*
 * get_origin   - Return origin (ASnnnn) given a network designation
 *
 * char *get_origin(char *net_designation)
 *
 * Returns:     0 - Error occurred, unable to get origin
 *              !0  Pointer to origin string
 *
 * Define STANDALONE to use this as a client.  Also define EXAMPLE_NET for
 * an example for the truly clueless...
 *
 *      20-May-1995     Ehud Gavron     gavron@aces.com
 *      28-Apr-2000                     Return error if no string
 */

/* The following are used to determine which service at which host to
   connect to.  A getenv() of the following elements occurs at run-time,
   which may override these values. */

#define RA_SERVER "whois.ra.net"
#define RA_SERVICE "whois"

/* The following determines what fields will be returned for the -A value
   (/AS_LOOKUP for VMS).  This is the "origin" of the route entry in the
   RADB. */

#define DATA_DELIMITER "origin:"

/* Since now the RADB has multiple route objects, we will list only the
   origin of the most specific one.  To do so we actually have to parse
   the route lines and look for the most specific route.  To do so we
   parse:
                net.net.net.net/prefix

   and use the most specific (largest) prefix.  The following determine
   how we get this.  */

#define ROUTE_DELIMITER "route:"
#define PREFIX_DELIMITER "/"

#ifdef STANDALONE
#ifdef __vms
#include "multinet_root:[multinet.include.sys]types.h"
#include "multinet_root:[multinet.include.sys]socket.h"
#include "multinet_root:[multinet.include.netinet]in.h"
#include <stdio.h>
#include "multinet_root:[multinet.include]netdb.h"
#define perror socket_perror
#define write socket_write
#define read socket_read
#define close socket_close
#else /* not VMS */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <netdb.h>
#endif /* VMS */
#endif /* STANDALONE */

#ifndef boolean
#define boolean int
#endif

#ifndef TRUE
#define TRUE (1==1)
#endif

#ifndef FALSE
#define FALSE (!(TRUE))
#endif
#define MAXREPLYLEN 8192

#ifdef STANDALONE
main(argc,argv)
int argc;
char **argv;
{
        char buffer[100];
        char *p;
        char *get_origin();
#ifdef EXAMPLE_NET
        strcpy(buffer,"192.195.240.0/24");
#else /* 6.3.0 null terminate buffer in standalone: */
	strncpy(buffer,argv[1],sizeof(buffer));
	buffer[sizeof(buffer)-1] = '\0';
#endif /* EXAMPLE_NET */
        p = get_origin(buffer);
        if (p) {
	   strncpy(buffer,p,sizeof(buffer));
	   buffer[sizeof(buffer)-1] = '\0';
           Fprintf(stdout,"origin is: %s\n",buffer);
        } else {
           Fprintf(stderr,"unable to get origin.\n");
        }
}
#endif /* STANDALONE */

char *get_origin(net)
char *net;
{
        char *i,*j,*k;
        char tmp[100],tmp2[100],tmp3[100]; /* store string delimiters */
        char tmp4[100];                 /* here's where we store the AS */
        static  char origin[100];       /* the returned route origin */
        char *rp;                       /* pointer to route: line */
        char *pp;                       /* pointer to /prefix part of route */
        int prefix;                     /* prefix off this line (decimal) */
        int best_prefix;                /* best prefix thus far */
        int s, n, count;
        char buf[256];
        boolean done;
        static char reply[MAXREPLYLEN];
        struct sockaddr_in sin;
        struct hostent *hp;
        struct servent *sp;
        char *getenv();

        /*
         * Get the IP address of the host which serves the routing arbiter
         * database.  We use RA_SERVER.  On the offchance that someone wants
         * to query another database, we check for the environment variable
         * RA_SERVER to have been set.
         */
        if ((i = getenv("RA_SERVER")) == 0) {
           strcpy(tmp,RA_SERVER);
        } else {
           strncpy(tmp,i,sizeof(tmp));
           tmp[(sizeof(tmp))-1] = '\0';          /* strncpy may not null term */
        }

        hp = gethostbyname(tmp);
        if (hp == NULL) {
           Fprintf(stderr, "get_origin: localhost unknown%s",terminator);
           return(0);
        }

        /*
         *  Create an IP-family socket on which to make the connection
         */

        s = socket(hp->h_addrtype, SOCK_STREAM, 0);
        if (s < 0) {
           perror("get_origin: socket");
           return(0);
        }

        /*
         *  Get the TCP port number of the "whois" server.
         *  Again if this needs to be updated, the environment variable
         *  RA_SERVICE should be set.
         */
        if ((i = getenv("RA_SERVICE")) == 0) {
           strcpy(tmp,RA_SERVICE);
        } else {
           strncpy(tmp,i,sizeof(tmp));
           tmp[(sizeof(tmp))-1] = '\0';          /* strncpy may not null term */
        }

        sp = getservbyname(tmp,"tcp");
        if (sp == NULL) {
           Fprintf(stderr, "get_origin: getservbyname: unknown service%s",terminator);
           return(0);
        }

        /*
         *  Create a "sockaddr_in" structure which describes the remote
         *  IP address we want to connect to (from gethostbyname()) and
         *  the remote TCP port number (from getservbyname()).
         */

        sin.sin_family = hp->h_addrtype;
        bcopy(hp->h_addr, (caddr_t)&sin.sin_addr, hp->h_length);
        sin.sin_port = sp->s_port;

        /*
         *  Connect to that address...
         */

        if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
           perror("get_origin: connect");
           return(0);
        }

        /*
         * Now send the request out to the server...
         */

        done = FALSE;
        snprintf(buf,sizeof(buf),"%s\r\n",net);
        write(s, buf, strlen(buf));

        /*
         * Now get the entire answer in one long buffer...
         */
        count = 0;
        while ((n = read(s, buf, sizeof(buf))) > 0) {
	    if (count + n >= MAXREPLYLEN) break;
            strcpy((char *)&reply[count],(char *)buf);
            count += n;
        }

        if (n < 0) {
            perror("get_origin: read");
            return(0);
        }

        reply[count] = '\0';    /* Terminate it - thanks Joey! */

        /*
         * sometimes there's no answer
         */
        if (strncmp(reply, "%%  No entries found for the selected source(s).",
            strlen("%%  No entries found for the selected source(s).")) ==0) {
           return "NONE";
        }

        /*
         * So now we have a large string, somewhere in which we can
         * find  origin:*AS%%%%%%<lf>.  We parse this into AS%%%%%.
         */

        if ((i = getenv("DATA_DELIMITER")) == 0) {
           strcpy(tmp,DATA_DELIMITER);
        } else {
           strncpy(tmp,i,sizeof(tmp));
           tmp[(sizeof(tmp))-1] = '\0';          /* strncpy may not null term */
        }

        /* TMP2 will have the route delimiter... */

        if ((i = getenv("ROUTE_DELIMITER")) == 0) {
           strcpy(tmp2,ROUTE_DELIMITER);
        } else {
           strncpy(tmp2,i,sizeof(tmp2));
           tmp2[(sizeof(tmp2))-1] = '\0';          /* strncpy may not null term */
        }

        if ((i = getenv("PREFIX_DELIMITER")) == 0) {
           strcpy(tmp3,PREFIX_DELIMITER);
        } else {
           strncpy(tmp3,i,sizeof(tmp3));
           tmp3[(sizeof(tmp3))-1] = '\0';          /* strncpy may not null term */
        }

/*
 * The next while statement was put in because of SPRINTLINK's ingeneous
 * Reasonable Default announcement project.  They registered nets in the
 * RADB of the ilk of 0.0.0.0/1, 128.0.0.0/1, 192..../2, etc... just so
 * that ANS wouldn't be such a pain in the butt.
 *
 * For us this means instead of taking the first origin...we take the best...
 */

/*
 * Initialize it so far as we've seen no prefixes, and are still looking
 * for route entries...
 */
        best_prefix = 0;                /* 0 bits is not very specific */
        done = FALSE;                   /* not done finding route: entries */

        rp = (char *)reply;             /* initialize main pointer to buffer */
        origin[0]='\0';                 /* initialize returned string */
        reply[MAXREPLYLEN-1]='\0';

        rp = (char *)strstr(rp,tmp2);   /* Find route: in the string */
        while (rp != 0) {               /* If there is such a thing... */
                                        /*  find it again later */
           pp = (char *)strstr(rp,tmp3);        /* Find / in the route entry */
           if (pp == 0) {               /* No prefix... */
              prefix = 0;               /* So we bias it out of here */
           } else {
              prefix = atoi(pp+1);      /* convert to decimal*/
           }

           if (prefix >= best_prefix) { /* it's equal to or better */
              i = (char *)strstr(pp,tmp);       /* find origin: delimiter */
              if (i != 0) {                     /* it's nice if there is one */
                 i += strlen(DATA_DELIMITER);   /* skip delimiter... */
                 i++;                           /* and the colon... */
                 while ((*i == ' ' || *i == 9) && (i-reply) < MAXREPLYLEN)
			 i++;	                /* skip spaces */
                 /* i now points to start of origin AS string */
                 j = i;                         /* terminate... */
                 while (*j >= '0' && (j-reply) < MAXREPLYLEN)
			 j++;
                 if (prefix > best_prefix) {
                    strcpy(origin,"/");         /* put a slash in */
                    best_prefix = prefix;               /* update best */
                 } else {
                    strcat(origin,"/");         /* put a mutiple as separator*/
                 }
		 if (j >= i + sizeof(tmp4))
			 j = i + sizeof(tmp4) - 1;
                 strncpy(tmp4,i,(j-i));         /* copy new origin */
                 tmp4[j-i] = '\0';              /* null terminate it */
                 if (!(strstr(origin,tmp4))) {  /* if it's not a dup */
                    strncat(origin,i,(j-i));    /*  stick it in */
                 } else {
                    if (prefix == best_prefix)  /* Otherwise remove slash */
                       origin[strlen(origin)-1] = '\0';
                 } /* end if not a dup */
              } /* end if origin found */
           } /* endif  prefix > best_prefix */
           rp = (char *)strstr(rp+1,tmp2);      /* Find route: in the string */
        } /* end while */
        /*
         * Go home...
         */
        close(s);
        if (best_prefix != 0) {                 /* did we get anything? */
           return((char *)&origin[1]);          /* strip off leading slash */
        } else {
           return(0);
        }
}

short getshort(ptr)
char *ptr;
{
    union {
        short retval;
        char ch[2];
    } foo;

    foo.ch[0] = (*ptr & 0xff);
    foo.ch[1] = (*(ptr+1) & 0xff);

    return (foo.retval);
}

char *doresolve (name)
char *name;
{
  int query=QUERY;
  int qtype=T_SOA;
  int qclass=C_IN;
  unsigned char buf[256];
  char *ans;
  int blen, alen, got;
  int anssiz, i;
  short shrt;
  HEADER *h;
  char *contact_ptr;
  int ptr;

  anssiz = 512;
  ans = (char *)malloc(anssiz);
  if (!ans) {
    return(0);
  }

  blen = res_mkquery(query,name,qclass,qtype,NULL,0,NULL,(u_char *)buf,sizeof(buf));
  if (blen < 0) {
    return (0);
  }

  alen = res_send((unsigned char *)buf,blen,(unsigned char *)ans,anssiz);
  if (alen == -1) {
    return (0);
  }

  if (alen < 12) {
    return (0);
  }

  h = (HEADER *)ans;

  h->id = ntohs(h->id);
  h->qdcount = ntohs(h->qdcount);
  h->ancount = ntohs(h->ancount);
  h->nscount = ntohs(h->nscount);
  h->arcount = ntohs(h->arcount);

  if (h->ancount == 0) return(0);

  ptr = 12;     /* point at first question field */
  for (i=0; i< (int)h->qdcount && ptr<alen; i++) {
    ptr=doqd((unsigned char *)ans,ptr);
  }

  for (i=0; i< (int)h->ancount && ptr<alen; i++) {
    ptr=dorr((unsigned char *)ans,ptr,&contact_ptr);
  }

  return (contact_ptr);
}

doqd(ans,off)
unsigned char *ans;
int off;
{
    char name[256];

    name[0]=0;
    off = doname(ans,off,name);
    off = dotype(ans,off);
    off = doclass(ans,off);
    return (off);
}

dorr(ans,off,contact_ptr)
unsigned char *ans;
int off;
char **contact_ptr;
{
    int class, typ;
    char name[256];

    name[0]=0;
    off = doname(ans,off,name);
    typ = ntohs(getshort(ans+off));
    off = dotype(ans,off);
    class = ntohs(getshort(ans+off));
    off = doclass(ans,off);
    off = dottl(ans,off);
    off = dordata(ans,off,class,typ,name,contact_ptr);
    return(off);
}

doname(ans,off,name)
int off;
unsigned char *ans;
char *name;
{
    int newoff, i;
    char tmp[50];

        /* redirect? */
    if ((*(ans+off) & 0xc0) == 0xc0) {
        newoff = getshort(ans+off);
        newoff = 0x3fff & ntohs(newoff);
        doname(ans,newoff,name);
        return (off+2);
    }
        /* end of string */
    if (*(ans+off) == 0) {
        strcat(name," ");
        return(off+1);
    }
        /* token */
    for (i=1; i<=(int)*(ans+off); i++)
        tmp[i-1]=ans[off+i];
    tmp[i-1] = '.';
    tmp[i]=0;
    strcat(name,tmp);
    return (doname(ans,off+1+(*(ans+off)), name));
}

dotype(ans,off)
int off;
unsigned char *ans;
{
    return(off+2);
}

doclass(ans,off)
int off;
unsigned char *ans;
{
    return(off+2);
}

dottl(ans,off)
int off;
unsigned char *ans;
{
    return(off+4);
}

dordata(ans,off,class,typ,fname,contact_ptr)
unsigned char *ans;
int off,class,typ;
char *fname;
char **contact_ptr;
{
    int len = ntohs(getshort(ans+off));
    int retval = off+len+2;
    int i,j;
    char name[256];

    off += 2;
    switch (typ) {
        case T_SOA:
            name[0]=0;
            off = doname(ans,off,name);
            name[0]=0;
            off = doname(ans,off,name);
            *contact_ptr=name;
            return (0);
        default:
            return (0);
    }
}

/*
        The VMS command line interface, DCL, uppercases all unquoted input.
        By default this program can be executed via
                $ mc location:traceroute options

        However, since this program needs case sensitivity for the various
        options to work, it is defined as an alias ``symbol'' with open
        quotes:
                $ traceroute == "location:traceroute """

        Unfortunately, this has the side effects of making argc=2, where
        argv[0] is the image location and name, and argv[1] is the entire
        option line.  Thus for VMS we need to break the options up...

        Note that if the symbol VMS_CLD is defined, then this is not used
        at all, but rather the VMS Command Language Definition facility
        is used.

*/

void AbortIfNull (ThePointer)
char *ThePointer;
{
        if (ThePointer == NULL) {
                Fprintf(stderr, "bad flags on that switch!%s",terminator);
                exit(666);
        };
}

#ifdef __vms


fixargs(a,b,c)
int *a;                 /* argc */
char **b;               /* argv */
char **c;               /* av */
{
        char *ptr, *space;
        /* Set the image name */
        c[0] = b[0];

        /* Initialize pointers */
        *a = 1;
        ptr = b[1];
        if (*ptr == ' ') ptr++;         /* eliminate first space */

        /* Delineate all strings ending with space */
        while ((space = strchr(ptr,' ')) != 0) {
           *space = '\0';
           c[(*a)++] = ptr;
           ptr = space + 1;
        }

        /* Transfer last one - ending with null */
        c[*a] = ptr;

        /* Update argc */
        (*a)++;
}

#endif /* vms */