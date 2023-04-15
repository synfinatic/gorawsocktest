// My code heavily inspired by and frankly stolen from traceroute available on: ftp://ftp.ee.lbl.gov/

/*
 * Copyright (c) 1988, 1989, 1991, 1994, 1995, 1996, 1997, 1998, 1999, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ifaddrlist.h"
#include "findsaddr.h"
#include "traceroute.h"

#define Fprintf (void)fprintf
#define Printf (void)printf

int sndsock;			/* send (udp/icmp) socket file descriptor */

struct sockaddr whereto;	/* Who to try to reach */
struct sockaddr wherefrom;	/* Who we are */
int packlen;			/* total length of packet */
int minpacket;			/* min ip packet size */
int maxpacket = 32 * 1024;	/* max ip packet size */
int pmtu;			/* Path MTU Discovery (RFC1191) */

int options;			/* socket options */
int verbose;
int waittime = 5;		/* time to wait for response (in seconds) */
int nflag;			/* print addresses numerically */
int useicmp;			/* use icmp echo instead of udp packets */
int doipcksum = 1;		/* calculate ip checksums by default */
int optlen;			/* length of ip options */

char *prog;
char *device;
char *hostname;
char *source;

/* Host name and address list */
struct hostinfo {
	char *name;
	int n;
	u_int32_t *addrs;
};

/* Data section of the probe packet */
struct outdata {
	u_char seq;		/* sequence number of this packet */
	u_char ttl;		/* ttl packet left with */
	struct timeval tv;	/* time packet left */
};

struct ip *outip;		/* last output (udp) packet */
struct udphdr *outudp;		/* last output (udp) packet */
struct outdata *outdata;	/* last output (udp) packet */

extern int optind;
extern int opterr;
extern char *optarg;

static const char devnull[] = "/dev/null";
u_short ident;
u_short port = 32768 + 666;	/* start udp dest port # for probe packets */

u_short in_cksum(register u_short *, register int);
void send_probe(register int, int, register struct timeval *);
void usage(void);
int str2val(register const char *, register const char *, register int, register int); 
void	freehostinfo(struct hostinfo *);
void	getaddr(u_int32_t *, char *);
struct	hostinfo *gethostinfo(char *);

int
main(int argc, char **argv) {
	register int op, code, n;
	register char *cp;
	register const char *err;
	register u_char *outp;
	register u_int32_t *ap;
	register struct sockaddr_in *from = (struct sockaddr_in *)&wherefrom;
	register struct sockaddr_in *to = (struct sockaddr_in *)&whereto;
	register struct hostinfo *hi;
	int on = 1;
	register struct protoent *pe;
	register int ttl, probe, i;
	register int seq = 0;
	int tos = 0, settos = 0;
	register u_short off = 0;
	struct ifaddrlist *al;
	char errbuf[132];

	if (argv[0] == NULL)
		prog = "csocktest";
	else if ((cp = strrchr(argv[0], '/')) != NULL)
		prog = cp + 1;
	else
		prog = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "dnrvxi:p:s:")) != EOF)
		switch (op) {

		case 'd':
			options |= SO_DEBUG;
			break;

		case 'i':
			device = optarg;
			break;

		case 'n':
			++nflag;
			break;

		case 'p':
			port = (u_short)str2val(optarg, "port",
			    1, (1 << 16) - 1);
			break;

		case 'r':
			options |= SO_DONTROUTE;
			break;

		case 's':
			/*
			 * set the ip source address of the outbound
			 * probe (e.g., on a multi-homed host).
			 */
			source = optarg;
			break;

		case 'v':
			++verbose;
			break;

		case 'x':
			doipcksum = (doipcksum == 0);
			break;

		default:
			usage();
		}


	minpacket = sizeof(*outip) + sizeof(*outdata) + optlen;
    minpacket += sizeof(*outudp);
	packlen = minpacket;			/* minimum sized packet */

	if (!doipcksum)
		Fprintf(stderr, "%s: Warning: ip checksums disabled\n", prog);

	/* Process destination and optional packet size */
	switch (argc - optind) {
	case 2:
		packlen = str2val(argv[optind + 1], "packet length", minpacket, maxpacket);
		/* Fall through */

	case 1:
		hostname = argv[optind];
		hi = gethostinfo(hostname);
		setsin(to, hi->addrs[0]);
		if (hi->n > 1) {
			Fprintf(stderr,
		    "%s: Warning: %s has multiple addresses; using %s\n",
				prog, hostname, inet_ntoa(to->sin_addr));
        }
		hostname = hi->name;
		hi->name = NULL;
		freehostinfo(hi);
		break;

	default:
		usage();
	}

// XXX: Important?
// #ifdef HAVE_SETLINEBUF
	setlinebuf (stdout);
	/*
#else
	setvbuf(stdout, NULL, _IOLBF, 0);
#endif
*/

	outip = (struct ip *)malloc((unsigned)packlen);
	if (outip == NULL) {
		Fprintf(stderr, "%s: malloc: %s\n", prog, strerror(errno));
		exit(1);
	}
	memset((char *)outip, 0, packlen);

	outip->ip_v = IPVERSION;
#ifdef BYTESWAP_IP_HDR
    // Linux & Solaris
	outip->ip_len = htons(packlen);
	outip->ip_off = htons(off);
#else
    // BSD
	outip->ip_len = packlen;
	outip->ip_off = off;
#endif

	outp = (u_char *)(outip + 1);

    outip->ip_dst = to->sin_addr;

	outip->ip_hl = (outp - (u_char *)outip) >> 2;
	ident = (getpid() & 0xffff) | 0x8000;
    outip->ip_p = IPPROTO_UDP;

    outudp = (struct udphdr *)outp;
    outudp->uh_sport = htons(ident);
    outudp->uh_ulen = htons((u_short)(packlen - (sizeof(*outip) + optlen)));
    outdata = (struct outdata *)(outudp + 1);

	/* Insure the socket fds won't be 0, 1 or 2 */
	if (open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0) {
		Fprintf(stderr, "%s: open \"%s\": %s\n",
		    prog, devnull, strerror(errno));
		exit(1);
	}

    // Linux, BSD
	sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if (sndsock < 0) {
		Fprintf(stderr, "%s: raw socket: %s\n", prog, strerror(errno));
		exit(1);
	}

#ifdef SO_SNDBUF
    // Everything???
	if (setsockopt(sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&packlen,
	    sizeof(packlen)) < 0) {
		Fprintf(stderr, "%s: SO_SNDBUF: %s\n", prog, strerror(errno));
		exit(1);
	}
#endif
#ifdef IP_HDRINCL
    // Definitely BSD
	if (setsockopt(sndsock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
	    sizeof(on)) < 0) {
		Fprintf(stderr, "%s: IP_HDRINCL: %s\n", prog, strerror(errno));
		exit(1);
	}
#else
#ifdef IP_TOS
	if (settos && setsockopt(sndsock, IPPROTO_IP, IP_TOS,
	    (char *)&tos, sizeof(tos)) < 0) {
		Fprintf(stderr, "%s: setsockopt tos %d: %s\n",
		    prog, tos, strerror(errno));
		exit(1);
	}
#endif
#endif

	if (options & SO_DEBUG)
		(void)setsockopt(sndsock, SOL_SOCKET, SO_DEBUG, (char *)&on,
		    sizeof(on));
	if (options & SO_DONTROUTE)
		(void)setsockopt(sndsock, SOL_SOCKET, SO_DONTROUTE, (char *)&on,
		    sizeof(on));

	/* Get the interface address list */
	n = ifaddrlist(&al, errbuf);
	if (n < 0) {
		Fprintf(stderr, "%s: ifaddrlist: %s\n", prog, errbuf);
		exit(1);
	}
	Fprintf(stderr, "device: %s\t%08x\n", al->device, ntohl(al->addr));
	if (n == 0) {
		Fprintf(stderr,
		    "%s: Can't find any network interfaces\n", prog);
		exit(1);
	}

	/* Look for a specific device */
	if (device != NULL) {
		for (i = n; i > 0; --i, ++al)
			if (strcmp(device, al->device) == 0)
				break;
		if (i <= 0) {
			Fprintf(stderr, "%s: Can't find interface %.32s\n",
			    prog, device);
			exit(1);
		}
	}

	/* Determine our source address */
	if (source == NULL) {
		/*
		 * If a device was specified, use the interface address.
		 * Otherwise, try to determine our source address.
		 */
		if (device != NULL)
			setsin(from, al->addr);
		else if ((err = findsaddr(to, from)) != NULL) {
			Fprintf(stderr, "%s: findsaddr: %s\n",
			    prog, err);
			exit(1);
		}
	} else {
		hi = gethostinfo(source);
		source = hi->name;
		hi->name = NULL;
		/*
		 * If the device was specified make sure it
		 * corresponds to the source address specified.
		 * Otherwise, use the first address (and warn if
		 * there are more than one).
		 */
		if (device != NULL) {
			for (i = hi->n, ap = hi->addrs; i > 0; --i, ++ap)
				if (*ap == al->addr)
					break;
			if (i <= 0) {
				Fprintf(stderr,
				    "%s: %s is not on interface %.32s\n",
				    prog, source, device);
				exit(1);
			}
			setsin(from, *ap);
		} else {
			setsin(from, hi->addrs[0]);
			if (hi->n > 1)
				Fprintf(stderr,
			"%s: Warning: %s has multiple addresses; using %s\n",
				    prog, source, inet_ntoa(from->sin_addr));
		}
		freehostinfo(hi);
	}

    Fprintf(stderr, "device: %s\t\tsource: %s\n", device, source);

	/* Revert to non-privileged user after opening sockets */
	setgid(getgid());
	setuid(getuid());

	outip->ip_src = from->sin_addr;
// #ifndef IP_HDRINCL
    // Everything right?
	if (bind(sndsock, (struct sockaddr *)from, sizeof(*from)) < 0) {
		Fprintf(stderr, "%s: bind: %s\n",
		    prog, strerror(errno));
		exit (1);
	}
// #endif

	Fprintf(stderr, "%s to %s (%s)",
	    prog, hostname, inet_ntoa(to->sin_addr));
	if (source)
		Fprintf(stderr, " from %s", source);
	Fprintf(stderr, ", %d hops max, %d byte packets\n", 16, packlen);
	(void)fflush(stderr);

    struct timeval t1, t2;
    struct timezone tz;
    (void)gettimeofday(&t1, &tz);
    send_probe(++seq, 15, &t1);

	exit(0);
}

void
send_probe(register int seq, int ttl, register struct timeval *tp)
{
	register int cc;
	register struct udpiphdr *ui, *oui;
	struct ip tip;

	outip->ip_ttl = ttl;
	outip->ip_id = htons(ident + seq);

	/*
	 * In most cases, the kernel will recalculate the ip checksum.
	 * But we must do it anyway so that the udp checksum comes out
	 * right.
	 */
	if (doipcksum) {
		outip->ip_sum =
		    in_cksum((u_short *)outip, sizeof(*outip) + optlen);
		if (outip->ip_sum == 0)
			outip->ip_sum = 0xffff;
	}

	/* Payload */
	outdata->seq = seq;
	outdata->ttl = ttl;
	outdata->tv = *tp;

    outudp->uh_dport = htons(port + seq);

	if (doipcksum) {
		/* Checksum (we must save and restore ip header) */
		tip = *outip;
		ui = (struct udpiphdr *)outip;
		oui = (struct udpiphdr *)&tip;
		/* Easier to zero and put back things that are ok */
		memset((char *)ui, 0, sizeof(ui->ui_i));
		ui->ui_src = oui->ui_src;
		ui->ui_dst = oui->ui_dst;
		ui->ui_pr = oui->ui_pr;
		ui->ui_len = outudp->uh_ulen;
		outudp->uh_sum = 0;
		outudp->uh_sum = in_cksum((u_short *)ui, packlen);
		if (outudp->uh_sum == 0)
			outudp->uh_sum = 0xffff;
		*outip = tip;
	}

	/* XXX undocumented debugging hack */
	if (verbose > 1) {
		register const u_short *sp;
		register int nshorts, i;

		sp = (u_short *)outip;
		nshorts = (u_int)packlen / sizeof(u_short);
		i = 0;
		Printf("[ %d bytes", packlen);
		while (--nshorts >= 0) {
			if ((i++ % 8) == 0)
				Printf("\n\t");
			Printf(" %04x", ntohs(*sp++));
		}
		if (packlen & 1) {
			if ((i % 8) == 0)
				Printf("\n\t");
			Printf(" %02x", *(u_char *)sp);
		}
		Printf("]\n");
	}

	cc = sendto(sndsock, (char *)outip,
	    packlen, 0, &whereto, sizeof(whereto));

	if (cc < 0 || cc != packlen)  {
		if (cc < 0)
			Fprintf(stderr, "%s: sendto: %s\n",
			    prog, strerror(errno));
		Printf("%s: wrote %s %d chars, ret=%d\n",
		    prog, hostname, packlen, cc);
		(void)fflush(stdout);
	}
}

double
deltaT(struct timeval *t1p, struct timeval *t2p)
{
	register double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
	     (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}


/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(register u_short *addr, register int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(u_char *)w;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/* String to value with optional min and max. Handles decimal and hex. */
int
str2val(register const char *str, register const char *what,
    register int mi, register int ma)
{
	register const char *cp;
	register int val;
	char *ep;

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		val = (int)strtol(cp, &ep, 16);
	} else
		val = (int)strtol(str, &ep, 10);
	if (*ep != '\0') {
		Fprintf(stderr, "%s: \"%s\" bad value for %s \n",
		    prog, str, what);
		exit(1);
	}
	if (val < mi && mi >= 0) {
		if (mi == 0)
			Fprintf(stderr, "%s: %s must be >= %d\n",
			    prog, what, mi);
		else
			Fprintf(stderr, "%s: %s must be > %d\n",
			    prog, what, mi - 1);
		exit(1);
	}
	if (val > ma && ma >= 0) {
		Fprintf(stderr, "%s: %s must be <= %d\n", prog, what, ma);
		exit(1);
	}
	return (val);
}

struct hostinfo *
gethostinfo(register char *hostname)
{
	register int n;
	register struct hostent *hp;
	register struct hostinfo *hi;
	register char **p;
	register u_int32_t addr, *ap;

	if (strlen(hostname) > 64) {
		Fprintf(stderr, "%s: hostname \"%.32s...\" is too long\n",
		    prog, hostname);
		exit(1);
	}
	hi = calloc(1, sizeof(*hi));
	if (hi == NULL) {
		Fprintf(stderr, "%s: calloc %s\n", prog, strerror(errno));
		exit(1);
	}
	addr = inet_addr(hostname);
	if ((int32_t)addr != -1) {
		hi->name = strdup(hostname);
		hi->n = 1;
		hi->addrs = calloc(1, sizeof(hi->addrs[0]));
		if (hi->addrs == NULL) {
			Fprintf(stderr, "%s: calloc %s\n",
			    prog, strerror(errno));
			exit(1);
		}
		hi->addrs[0] = addr;
		return (hi);
	}

	hp = gethostbyname(hostname);
	if (hp == NULL) {
		Fprintf(stderr, "%s: unknown host %s\n", prog, hostname);
		exit(1);
	}
	if (hp->h_addrtype != AF_INET || hp->h_length != 4) {
		Fprintf(stderr, "%s: bad host %s\n", prog, hostname);
		exit(1);
	}
	hi->name = strdup(hp->h_name);
	for (n = 0, p = hp->h_addr_list; *p != NULL; ++n, ++p)
		continue;
	hi->n = n;
	hi->addrs = calloc(n, sizeof(hi->addrs[0]));
	if (hi->addrs == NULL) {
		Fprintf(stderr, "%s: calloc %s\n", prog, strerror(errno));
		exit(1);
	}
	for (ap = hi->addrs, p = hp->h_addr_list; *p != NULL; ++ap, ++p)
		memcpy(ap, *p, sizeof(*ap));
	return (hi);
}

void
setsin(register struct sockaddr_in *sin, register u_int32_t addr)
{

	memset(sin, 0, sizeof(*sin));
#ifdef HAVE_SOCKADDR_SA_LEN
	sin->sin_len = sizeof(*sin);
#endif
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
}

void
freehostinfo(register struct hostinfo *hi)
{
	if (hi->name != NULL) {
		free(hi->name);
		hi->name = NULL;
	}
	free((char *)hi->addrs);
	free((char *)hi);
}

void
getaddr(register u_int32_t *ap, register char *hostname)
{
	register struct hostinfo *hi;

	hi = gethostinfo(hostname);
	*ap = hi->addrs[0];
	freehostinfo(hi);
}

__dead void
usage(void)
{
	Fprintf(stderr,
	    "Usage: %s [-dnrvx] [-i iface]\n"
	    "\t[ -p port] [-s src_addr]\n"
	    "\thost [packetlen]\n", prog);
	exit(1);
}