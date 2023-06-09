/*
 * Copyright (c) 2023 Aaron Turner
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
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "findsaddr.h"
#include "ifaddrlist.h"
#include "traceroute.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

#define Fprintf (void)fprintf
#define Printf (void)printf

/* Host name and address list */
struct hostinfo {
	char *name;
	int n;
	u_int32_t *addrs;
};

struct old_outdata {
	u_char seq;		/* sequence number of this packet */
	u_char ttl;		/* ttl packet left with */
	struct timeval tv;	/* time packet left */
};

/* Data section of the probe packet */
union outdata {
	struct old_outdata old;
	char new[512];
};

u_char	packet[512];		/* last inbound (icmp) packet */

struct ip *outip;		/* last output (udp) packet */
struct udphdr *outudp;		/* last output (udp) packet */
union outdata *outdata;	/* last output (udp) packet */

int s;				/* receive (icmp) socket file descriptor */
int sndsock;			/* send (udp/icmp) socket file descriptor */

struct sockaddr whereto;	/* Who to try to reach */
struct sockaddr wherefrom;	/* Who we are */
int packlen;			/* total length of packet */

static const char devnull[] = "/dev/null";

extern int optind;
extern int opterr;
extern char *optarg;

/* Forwards */
void	freehostinfo(struct hostinfo *);
struct	hostinfo *gethostinfo(char *);
u_short	in_cksum(u_short *, int);
void	send_probe();
int	str2val(const char *, const char *, int, int);
__dead	void usage(void);
#ifndef HAVE_USLEEP
int	usleep(u_int);
#endif

char *prog;

int zeroIPLen = 0; // -z
int noRoute = 0; // -n
char *srcIP = "172.16.1.162";
char *dstIP = NULL; // required
int ttl = 10;
u_short ident = 0x1234;
u_int16_t srcPort = 5555; // -S
u_int16_t  dstPort = 6666; // -D
int bufSize = -1;
int count = 1;
char *device = NULL; // -i, optional
char *payload = "this is my payload datas"; // -p


int
main(int argc, char **argv)
{
	char *cp;
	const char *err;
	u_char *outp;
	u_int32_t *ap;
	struct sockaddr_in *from = (struct sockaddr_in *)&wherefrom;
	struct sockaddr_in *to = (struct sockaddr_in *)&whereto;
	struct hostinfo *hi;
	int on = 1;
	int i, op, n;
	struct ifaddrlist *al;
	char errbuf[132];

	if (argv[0] == NULL) {
		prog = "csocktest";
	} else if ((cp = strrchr(argv[0], '/')) != NULL) {
		prog = cp + 1;
	} else {
		prog = argv[0];
	}

	opterr = 0;
	while ((op = getopt(argc, argv, "nzb:c:i:d:D:s:S:p:")) != EOF) {
		switch (op) {
		case 'b': // bufsize
			bufSize = str2val(optarg, "bufsize", 0, (1 << 16) -1);
			break;

		case 'c': // count
			count = str2val(optarg, "count", 1, (1 << 16) -1);
			break;

		case 'i': // interface
			device = optarg;
			break;

		case 'n': // bypass routing table
			noRoute = 1;
			break;

		case 'D': // dest port
			dstPort = (u_short)str2val(optarg, "dstPort", 1, (1 << 16) - 1);
			break;

		case 'S': // source port
			srcPort = (u_short)str2val(optarg, "srcPort", 1, (1 << 16) - 1);
			break;

		case 'd': // dest IP
			dstIP = optarg;
			break;

		case 's': // source IP
			srcIP = optarg;
			break;

		case 'z': // set IP.Length = 0
			zeroIPLen = 1;
			break;

		case 'p': // payload
			payload = optarg;
			break; 

		default:
			usage();
		}
	}

	packlen = 20 + 8 + strlen(payload);			/* minimum sized packet */

	if (dstIP == NULL) {
		Fprintf(stderr, "Missing required -d <dstIP>\n");
		exit(-1);
	}

	// convert our src & dst IPs
	struct in_addr ipaddr;
	inet_aton(dstIP, &ipaddr);
	setsin(to, ipaddr.s_addr);
	inet_aton(srcIP, &ipaddr);
	setsin(from, ipaddr.s_addr);


#ifdef HAVE_SETLINEBUF
	setlinebuf (stdout);
#else
	setvbuf(stdout, NULL, _IOLBF, 0);
#endif

	outip = (struct ip *)malloc((unsigned)packlen);
	if (outip == NULL) {
		Fprintf(stderr, "%s: malloc: %s\n", prog, strerror(errno));
		exit(1);
	}
	memset((char *)outip, 0, packlen);

	outip->ip_v = IPVERSION;
#ifdef BYTESWAP_IP_HDR
	Fprintf(stderr, "we are using network byte order for IP len/off\n");
	outip->ip_len = htons(packlen);
	outip->ip_off = htons(0);
#else
	Fprintf(stderr, "we are using host byte order for IP len/off\n");
	outip->ip_len = packlen;
	outip->ip_off = 0;
#endif

	if (zeroIPLen) {
		outip->ip_len = 0;
	}

	outp = (u_char *)(outip + 1);
	outip->ip_dst = to->sin_addr;

	outip->ip_hl = (outp - (u_char *)outip) >> 2;
	outip->ip_p = IPPROTO_UDP;

	outudp = (struct udphdr *)outp;
	outudp->uh_sport = htons(srcPort);
	outudp->uh_ulen = htons((u_short)(packlen - (sizeof(*outip))));
	outdata = (union outdata *)(outudp + 1);

	/* Insure the socket fds won't be 0, 1 or 2 */
	if (open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0) {
		Fprintf(stderr, "%s: open \"%s\": %s\n", prog, devnull, strerror(errno));
		exit(1);
	}

	// open our SOCK_RAW
	sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sndsock < 0) {
		Fprintf(stderr, "%s: raw socket: %s\n", prog, strerror(errno));
		exit(1);
	}

#ifdef SO_SNDBUF
	if (bufSize != 0) {
		if (bufSize < 0)
			bufSize = packlen;
		if (setsockopt(sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&bufSize, sizeof(bufSize)) < 0) {
			Fprintf(stderr, "%s: SO_SNDBUF: %s\n", prog, strerror(errno));
			exit(1);
		}
		Fprintf(stderr, "we set SNDBUF to %d bytes\n", bufSize);
	}
#endif
#ifdef IP_HDRINCL
	Fprintf(stderr, "we set HDRINCL\n");
	if (setsockopt(sndsock, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0) {
		Fprintf(stderr, "%s: IP_HDRINCL: %s\n", prog, strerror(errno));
		exit(1);
	}
#endif

	/* Get the interface address list */
	n = ifaddrlist(&al, errbuf);
	if (n < 0) {
		Fprintf(stderr, "%s: ifaddrlist: %s\n", prog, errbuf);
		exit(1);
	}
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
			Fprintf(stderr, "%s: Can't find interface %.32s\n", prog, device);
			exit(1);
		}
	}

	/* Determine our source address */
	if (srcIP == NULL) {
		/*
		 * If a device was specified, use the interface address.
		 * Otherwise, try to determine our source address.
		 */
		if (device != NULL) {
			setsin(from, al->addr);
		} else if ((err = findsaddr(to, from)) != NULL) {
			Fprintf(stderr, "%s: findsaddr: %s\n", prog, err);
			exit(1);
		}
	} else {
		hi = gethostinfo(srcIP);
		srcIP = hi->name;
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
				Fprintf(stderr, "%s: %s is not on interface %.32s\n", prog, srcIP, device);
				exit(1);
			}
			setsin(from, *ap);
		} else {
			setsin(from, hi->addrs[0]);
			if (hi->n > 1)
				Fprintf(stderr,
			"%s: Warning: %s has multiple addresses; using %s\n", prog, srcIP, inet_ntoa(from->sin_addr));
		}
		freehostinfo(hi);
	}

	/* Revert to non-privileged user after opening sockets */
	setgid(getgid());
	setuid(getuid());

	outip->ip_src = from->sin_addr;
#ifndef IP_HDRINCL
	Fprintf(stderr, "we bind socket to %s\n", inet_ntoa(from->sin_addr));
	if (bind(sndsock, (struct sockaddr *)from, sizeof(*from)) < 0) {
		Fprintf(stderr, "%s: bind: %s\n",
		    prog, strerror(errno));
		exit (1);
	}
#endif

	Fprintf(stderr, "%s:%d -> %s:%d\n", srcIP, srcPort, dstIP, dstPort);
	for (int i = 0; i < count; i++)
		send_probe();
	// if we don't manually close, then we can't send _only_ 1 packet
	close(sndsock);
	exit(0);
}

void
send_probe()
{
	int cc;
	struct udpiphdr *ui, *oui;
	struct ip tip;

	outip->ip_ttl = ttl;
	outip->ip_id = htons(ident);

	/*
	 * In most cases, the kernel will recalculate the ip checksum.
	 * But we must do it anyway so that the udp checksum comes out
	 * right.
	 */
	outip->ip_sum = in_cksum((u_short *)outip, sizeof(*outip));
	if (outip->ip_sum == 0)
		outip->ip_sum = 0xffff;

	strncpy(outdata->new, payload, strlen(payload));

	outudp->uh_dport = htons(dstPort);

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

	/* XXX undocumented debugging hack */
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

#if !defined(IP_HDRINCL) && defined(IP_TTL)
	Fprintf(stderr, "we set setsockopt ttl\n");
	if (setsockopt(sndsock, IPPROTO_IP, IP_TTL,
	    (char *)&ttl, sizeof(ttl)) < 0) {
		Fprintf(stderr, "%s: setsockopt ttl %d: %s\n",
		    prog, ttl, strerror(errno));
		exit(1);
	}
#endif

	cc = sendto(sndsock, (char *)outip, packlen, 0, &whereto, sizeof(whereto));
	if (cc < 0 || cc != packlen)  {
		if (cc < 0) {
			Fprintf(stderr, "%s: sendto: %s\n", prog, strerror(errno));
		}
		Printf("%s: wrote %s %d chars, ret=%d\n", prog, dstIP, packlen, cc);
		(void)fflush(stdout);
	}
}


/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(register u_short *addr, register int len)
{
	int nleft = len;
	u_short *w = addr;
	u_short answer;
	int sum = 0;

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

struct hostinfo *
gethostinfo(register char *hostname)
{
	int n;
	struct hostent *hp;
	struct hostinfo *hi;
	char **p;
	u_int32_t addr, *ap;

	if (strlen(hostname) > 64) {
		Fprintf(stderr, "%s: hostname \"%.32s...\" is too long\n", prog, hostname);
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
			Fprintf(stderr, "%s: calloc %s\n", prog, strerror(errno));
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
setsin(register struct sockaddr_in *sin, register u_int32_t addr)
{

	memset(sin, 0, sizeof(*sin));
#ifdef HAVE_SOCKADDR_SA_LEN
	sin->sin_len = sizeof(*sin);
#endif
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
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
	} else {
		val = (int)strtol(str, &ep, 10);
	}

	if (*ep != '\0') {
		Fprintf(stderr, "%s: \"%s\" bad value for %s \n", prog, str, what);
		exit(1);
	}
	if (val < mi && mi >= 0) {
		if (mi == 0) {
			Fprintf(stderr, "%s: %s must be >= %d\n", prog, what, mi);
		} else {
			Fprintf(stderr, "%s: %s must be > %d\n", prog, what, mi - 1);
		}
		exit(1);
	}
	if (val > ma && ma >= 0) {
		Fprintf(stderr, "%s: %s must be <= %d\n", prog, what, ma);
		exit(1);
	}
	return (val);
}

__dead void
usage(void)
{
	Fprintf(stderr,
	    "Usage: %s [-nvz] [-b bufSize] [-c count] [-i iface] [-s srcIP] [-S srcPort] [-D dstPort]\n"
	    "\t[-p payload] -d dstIP\n", prog);
	exit(1);
}
