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

#ifndef lint
static const char copyright[] =
    "@(#) Copyright (c) 1988, 1989, 1991, 1994, 1995, 1996, 1997, 1998, 1999, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#)$Id: traceroute.c,v 1.68 2000/12/14 08:04:33 leres Exp $ (LBL)";
#endif

/*
 * traceroute host  - trace the route ip packets follow going to "host".
 *
 * Attempt to trace the route an ip packet would follow to some
 * internet host.  We find out intermediate hops by launching probe
 * packets with a small ttl (time to live) then listening for an
 * icmp "time exceeded" reply from a gateway.  We start our probes
 * with a ttl of one and increase by one until we get an icmp "port
 * unreachable" (which means we got to "host") or hit a max (which
 * defaults to 30 hops & can be changed with the -m flag).  Three
 * probes (change with -q flag) are sent at each ttl setting and a
 * line is printed showing the ttl, address of the gateway and
 * round trip time of each probe.  If the probe answers come from
 * different gateways, the address of each responding system will
 * be printed.  If there is no response within a 5 sec. timeout
 * interval (changed with the -w flag), a "*" is printed for that
 * probe.
 *
 * Probe packets are UDP format.  We don't want the destination
 * host to process them so the destination port is set to an
 * unlikely value (if some clod on the destination is using that
 * value, it can be changed with the -p flag).
 *
 * A sample use might be:
 *
 *     [yak 71]% traceroute nis.nsf.net.
 *     traceroute to nis.nsf.net (35.1.1.48), 30 hops max, 56 byte packet
 *      1  helios.ee.lbl.gov (128.3.112.1)  19 ms  19 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  39 ms  19 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  39 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  39 ms  40 ms  39 ms
 *      5  ccn-nerif22.Berkeley.EDU (128.32.168.22)  39 ms  39 ms  39 ms
 *      6  128.32.197.4 (128.32.197.4)  40 ms  59 ms  59 ms
 *      7  131.119.2.5 (131.119.2.5)  59 ms  59 ms  59 ms
 *      8  129.140.70.13 (129.140.70.13)  99 ms  99 ms  80 ms
 *      9  129.140.71.6 (129.140.71.6)  139 ms  239 ms  319 ms
 *     10  129.140.81.7 (129.140.81.7)  220 ms  199 ms  199 ms
 *     11  nic.merit.edu (35.1.1.48)  239 ms  239 ms  239 ms
 *
 * Note that lines 2 & 3 are the same.  This is due to a buggy
 * kernel on the 2nd hop system -- lbl-csam.arpa -- that forwards
 * packets with a zero ttl.
 *
 * A more interesting example is:
 *
 *     [yak 72]% traceroute allspice.lcs.mit.edu.
 *     traceroute to allspice.lcs.mit.edu (18.26.0.115), 30 hops max
 *      1  helios.ee.lbl.gov (128.3.112.1)  0 ms  0 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  19 ms  19 ms  19 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  19 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  19 ms  39 ms  39 ms
 *      5  ccn-nerif22.Berkeley.EDU (128.32.168.22)  20 ms  39 ms  39 ms
 *      6  128.32.197.4 (128.32.197.4)  59 ms  119 ms  39 ms
 *      7  131.119.2.5 (131.119.2.5)  59 ms  59 ms  39 ms
 *      8  129.140.70.13 (129.140.70.13)  80 ms  79 ms  99 ms
 *      9  129.140.71.6 (129.140.71.6)  139 ms  139 ms  159 ms
 *     10  129.140.81.7 (129.140.81.7)  199 ms  180 ms  300 ms
 *     11  129.140.72.17 (129.140.72.17)  300 ms  239 ms  239 ms
 *     12  * * *
 *     13  128.121.54.72 (128.121.54.72)  259 ms  499 ms  279 ms
 *     14  * * *
 *     15  * * *
 *     16  * * *
 *     17  * * *
 *     18  ALLSPICE.LCS.MIT.EDU (18.26.0.115)  339 ms  279 ms  279 ms
 *
 * (I start to see why I'm having so much trouble with mail to
 * MIT.)  Note that the gateways 12, 14, 15, 16 & 17 hops away
 * either don't send ICMP "time exceeded" messages or send them
 * with a ttl too small to reach us.  14 - 17 are running the
 * MIT C Gateway code that doesn't send "time exceeded"s.  God
 * only knows what's going on with 12.
 *
 * The silent gateway 12 in the above may be the result of a bug in
 * the 4.[23]BSD network code (and its derivatives):  4.x (x <= 3)
 * sends an unreachable message using whatever ttl remains in the
 * original datagram.  Since, for gateways, the remaining ttl is
 * zero, the icmp "time exceeded" is guaranteed to not make it back
 * to us.  The behavior of this bug is slightly more interesting
 * when it appears on the destination system:
 *
 *      1  helios.ee.lbl.gov (128.3.112.1)  0 ms  0 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  19 ms  39 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  19 ms  39 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  39 ms  40 ms  19 ms
 *      5  ccn-nerif35.Berkeley.EDU (128.32.168.35)  39 ms  39 ms  39 ms
 *      6  csgw.Berkeley.EDU (128.32.133.254)  39 ms  59 ms  39 ms
 *      7  * * *
 *      8  * * *
 *      9  * * *
 *     10  * * *
 *     11  * * *
 *     12  * * *
 *     13  rip.Berkeley.EDU (128.32.131.22)  59 ms !  39 ms !  39 ms !
 *
 * Notice that there are 12 "gateways" (13 is the final
 * destination) and exactly the last half of them are "missing".
 * What's really happening is that rip (a Sun-3 running Sun OS3.5)
 * is using the ttl from our arriving datagram as the ttl in its
 * icmp reply.  So, the reply will time out on the return path
 * (with no notice sent to anyone since icmp's aren't sent for
 * icmp's) until we probe with a ttl that's at least twice the path
 * length.  I.e., rip is really only 7 hops away.  A reply that
 * returns with a ttl of 1 is a clue this problem exists.
 * Traceroute prints a "!" after the time if the ttl is <= 1.
 * Since vendors ship a lot of obsolete (DEC's Ultrix, Sun 3.x) or
 * non-standard (HPUX) software, expect to see this problem
 * frequently and/or take care picking the target host of your
 * probes.
 *
 * Other possible annotations after the time are !H, !N, !P (got a host,
 * network or protocol unreachable, respectively), !S or !F (source
 * route failed or fragmentation needed -- neither of these should
 * ever occur and the associated gateway is busted if you see one).  If
 * almost all the probes result in some kind of unreachable, traceroute
 * will give up and exit.
 *
 * Notes
 * -----
 * This program must be run by root or be setuid.  (I suggest that
 * you *don't* make it setuid -- casual use could result in a lot
 * of unnecessary traffic on our poor, congested nets.)
 *
 * This program requires a kernel mod that does not appear in any
 * system available from Berkeley:  A raw ip socket using proto
 * IPPROTO_RAW must interpret the data sent as an ip datagram (as
 * opposed to data to be wrapped in a ip datagram).  See the README
 * file that came with the source to this program for a description
 * of the mods I made to /sys/netinet/raw_ip.c.  Your mileage may
 * vary.  But, again, ANY 4.x (x < 4) BSD KERNEL WILL HAVE TO BE
 * MODIFIED TO RUN THIS PROGRAM.
 *
 * The udp port usage may appear bizarre (well, ok, it is bizarre).
 * The problem is that an icmp message only contains 8 bytes of
 * data from the original datagram.  8 bytes is the size of a udp
 * header so, if we want to associate replies with the original
 * datagram, the necessary information must be encoded into the
 * udp header (the ip id could be used but there's no way to
 * interlock with the kernel's assignment of ip id's and, anyway,
 * it would have taken a lot more kernel hacking to allow this
 * code to set the ip id).  So, to allow two or more users to
 * use traceroute simultaneously, we use this task's pid as the
 * source port (the high bit is set to move the port number out
 * of the "likely" range).  To keep track of which probe is being
 * replied to (so times and/or hop counts don't get confused by a
 * reply that was delayed in transit), we increment the destination
 * port number before each probe.
 *
 * Don't use this as a coding example.  I was trying to find a
 * routing problem and this code sort-of popped out after 48 hours
 * without sleep.  I was amazed it ever compiled, much less ran.
 *
 * I stole the idea for this program from Steve Deering.  Since
 * the first release, I've learned that had I attended the right
 * IETF working group meetings, I also could have stolen it from Guy
 * Almes or Matt Mathis.  I don't know (or care) who came up with
 * the idea first.  I envy the originators' perspicacity and I'm
 * glad they didn't keep the idea a secret.
 *
 * Tim Seaver, Ken Adelman and C. Philip Wood provided bug fixes and/or
 * enhancements to the original distribution.
 *
 * I've hacked up a round-trip-route version of this that works by
 * sending a loose-source-routed udp datagram through the destination
 * back to yourself.  Unfortunately, SO many gateways botch source
 * routing, the thing is almost worthless.  Maybe one day...
 *
 *  -- Van Jacobson (van@ee.lbl.gov)
 *     Tue Dec 20 03:50:13 PST 1988
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
	char new[24];
};

u_char	packet[512];		/* last inbound (icmp) packet */

struct ip *outip;		/* last output (udp) packet */
struct udphdr *outudp;		/* last output (udp) packet */
union outdata *outdata;	/* last output (udp) packet */
struct icmp *outicmp;		/* last output (icmp) packet */

int s;				/* receive (icmp) socket file descriptor */
int sndsock;			/* send (udp/icmp) socket file descriptor */

struct sockaddr whereto;	/* Who to try to reach */
struct sockaddr wherefrom;	/* Who we are */
int packlen;			/* total length of packet */
int minpacket;			/* min ip packet size */
int maxpacket = 32 * 1024;	/* max ip packet size */
int pmtu;			/* Path MTU Discovery (RFC1191) */

char *prog;
char *source;
char *hostname;
char *device;
static const char devnull[] = "/dev/null";

int max_ttl = 30;
int first_ttl = 1;
u_short ident;
u_short port = 32768 + 666;	/* start udp dest port # for probe packets */

int options;			/* socket options */
int verbose;
int nflag;			/* print addresses numerically */
#ifdef CANT_HACK_IPCKSUM
int doipcksum = 0;		/* don't calculate ip checksums by default */
#else
int doipcksum = 1;		/* calculate ip checksums by default */
#endif
int optlen;			/* length of ip options */

extern int optind;
extern int opterr;
extern char *optarg;

/* Forwards */
void	freehostinfo(struct hostinfo *);
struct	hostinfo *gethostinfo(char *);
u_short	in_cksum(u_short *, int);
int	main(int, char **);
void	send_probe(int, int, struct timeval *);
int	str2val(const char *, const char *, int, int);
__dead	void usage(void);
#ifndef HAVE_USLEEP
int	usleep(u_int);
#endif

int
main(int argc, char **argv)
{
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
	register int lsrr = 0;
	register u_short off = 0;
	struct ifaddrlist *al;
	char errbuf[132];

	if (argv[0] == NULL)
		prog = "traceroute";
	else if ((cp = strrchr(argv[0], '/')) != NULL)
		prog = cp + 1;
	else
		prog = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "dFnrvxf:I:i:m:p:s:")) != EOF)
		switch (op) {

		case 'd':
			options |= SO_DEBUG;
			break;

		case 'f':
			first_ttl = str2val(optarg, "first ttl", 1, 255);
			break;

		case 'F':
			off = IP_DF;
			break;

		case 'I':
			ident = (u_short)str2val(optarg, "ip id", 1, 65535);
			Fprintf(stderr, "using ip id: 0x%04x\n", ident);
			break;

		case 'i':
			device = optarg;
			break;

		case 'm':
			max_ttl = str2val(optarg, "max ttl", 1, 255);
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

	if (first_ttl > max_ttl) {
		Fprintf(stderr,
		    "%s: first ttl (%d) may not be greater than max ttl (%d)\n",
		    prog, first_ttl, max_ttl);
		exit(1);
	}

	if (!doipcksum)
		Fprintf(stderr, "%s: Warning: ip checksums disabled\n", prog);

	minpacket = sizeof(*outip) + sizeof(outdata->new) + optlen;
	minpacket += sizeof(*outudp);
	packlen = minpacket;			/* minimum sized packet */

	/* Process destination and optional packet size */
	switch (argc - optind) {

	case 2:
		packlen = str2val(argv[optind + 1],
		    "packet length", minpacket, maxpacket);
		/* Fall through */

	case 1:
		hostname = argv[optind];
		hi = gethostinfo(hostname);
		setsin(to, hi->addrs[0]);
		if (hi->n > 1)
			Fprintf(stderr,
		    "%s: Warning: %s has multiple addresses; using %s\n",
				prog, hostname, inet_ntoa(to->sin_addr));
		hostname = hi->name;
		hi->name = NULL;
		freehostinfo(hi);
		break;

	default:
		usage();
	}

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
	outip->ip_off = htons(off);
#else
	Fprintf(stderr, "we are using host byte order for IP len/off\n");
	outip->ip_len = packlen;
	outip->ip_off = off;
#endif
	outp = (u_char *)(outip + 1);
	outip->ip_dst = to->sin_addr;

	outip->ip_hl = (outp - (u_char *)outip) >> 2;
	if (0 == ident) {
		ident = (getpid() & 0xffff) | 0x8000;
	}
	outip->ip_p = IPPROTO_UDP;

	outudp = (struct udphdr *)outp;
	outudp->uh_sport = htons(ident);
	outudp->uh_ulen = htons((u_short)(packlen - (sizeof(*outip) + optlen)));
	outdata = (union outdata *)(outudp + 1);

	cp = "icmp";
	if ((pe = getprotobyname(cp)) == NULL) {
		Fprintf(stderr, "%s: unknown protocol %s\n", prog, cp);
		exit(1);
	}

	/* Insure the socket fds won't be 0, 1 or 2 */
	if (open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0) {
		Fprintf(stderr, "%s: open \"%s\": %s\n",
		    prog, devnull, strerror(errno));
		exit(1);
	}
	if ((s = socket(AF_INET, SOCK_RAW, pe->p_proto)) < 0) {
		Fprintf(stderr, "%s: icmp socket: %s\n", prog, strerror(errno));
		exit(1);
	}
	if (options & SO_DEBUG)
		(void)setsockopt(s, SOL_SOCKET, SO_DEBUG, (char *)&on,
		    sizeof(on));
	if (options & SO_DONTROUTE)
		(void)setsockopt(s, SOL_SOCKET, SO_DONTROUTE, (char *)&on,
		    sizeof(on));

	sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sndsock < 0) {
		Fprintf(stderr, "%s: raw socket: %s\n", prog, strerror(errno));
		exit(1);
	}

#ifdef SO_SNDBUF
	Fprintf(stderr, "we set SNDBUF\n");
	if (setsockopt(sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&packlen,
	    sizeof(packlen)) < 0) {
		Fprintf(stderr, "%s: SO_SNDBUF: %s\n", prog, strerror(errno));
		exit(1);
	}
#endif
#ifdef IP_HDRINCL
	Fprintf(stderr, "we set HDRINCL\n");
	if (setsockopt(sndsock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
	    sizeof(on)) < 0) {
		Fprintf(stderr, "%s: IP_HDRINCL: %s\n", prog, strerror(errno));
		exit(1);
	}
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

	/* Revert to non-privileged user after opening sockets */
	setgid(getgid());
	setuid(getuid());

	outip->ip_src = from->sin_addr;
#ifndef IP_HDRINCL
	if (bind(sndsock, (struct sockaddr *)from, sizeof(*from)) < 0) {
		Fprintf(stderr, "%s: bind: %s\n",
		    prog, strerror(errno));
		exit (1);
	}
#endif

	Fprintf(stderr, "%s to %s (%s)",
	    prog, hostname, inet_ntoa(to->sin_addr));
	if (source)
		Fprintf(stderr, " from %s", source);
	Fprintf(stderr, ", %d hops max, %d byte packets\n", max_ttl, packlen);
	(void)fflush(stderr);

	for (ttl = first_ttl; ttl <= max_ttl; ++ttl) {
		u_int32_t lastaddr = 0;
		int gotlastaddr = 0;
		int got_there = 0;
		int unreachable = 0;
		int sentfirst = 0;

		for (probe = 0; probe < 3; ++probe) {
			register int cc;
			struct timeval t1, t2;
			struct timezone tz;
			register struct ip *ip;

			(void)gettimeofday(&t1, &tz);
			send_probe(++seq, ttl, &t1);
			++sentfirst;
			(void)fflush(stdout);
		}
		putchar('\n');
		break;
	}
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

	/* Payload 
	outdata->seq = seq;
	outdata->ttl = ttl;
	outdata->tv = *tp;
	*/
	strncpy(outdata->new, "this is my payload datas", 24);

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

#if !defined(IP_HDRINCL) && defined(IP_TTL)
	if (setsockopt(sndsock, IPPROTO_IP, IP_TTL,
	    (char *)&ttl, sizeof(ttl)) < 0) {
		Fprintf(stderr, "%s: setsockopt ttl %d: %s\n",
		    prog, ttl, strerror(errno));
		exit(1);
	}
#endif

	cc = sendto(sndsock, (char *)outip, packlen, 0, &whereto, sizeof(whereto));
	if (cc < 0 || cc != packlen)  {
		if (cc < 0)
			Fprintf(stderr, "%s: sendto: %s\n",
			    prog, strerror(errno));
		Printf("%s: wrote %s %d chars, ret=%d\n",
		    prog, hostname, packlen, cc);
		(void)fflush(stdout);
	}
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

__dead void
usage(void)
{
	extern char version[];

	Fprintf(stderr, "Version %s\n", version);
	Fprintf(stderr,
	    "Usage: %s [-dFnrvx] [-g gateway] [-i iface] [-f first_ttl]\n"
	    "\t[-m max_ttl] [ -p port] [-s src_addr]\n"
	    "\thost [packetlen]\n", prog);
	exit(1);
}
