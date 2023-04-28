package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/synfinatic/gorawsocktest/pkg/rawlayers"
)

type CLI struct {
	BufSize   int    `kong:"short='b',help='Override SO_SNDBUF size. 0 = do not set.',default=-1"`
	Count     int    `kong:"short='c',help='Number of packets to send',default=1"`
	NoRoute   bool   `kong:"short='n',help='Tell the kernel to bypass routing table'"`
	Interface string `kong:"short='i',help='Interface to bind to'"`
	SrcIP     string `kong:"short='s',help='Source IP',default='172.16.1.162'"`
	DstIP     string `kong:"short='d',help='Destination IP',required"`
	SrcPort   uint16 `kong:"short='S',help='UDP source port',default='5555'"`
	DstPort   uint16 `kong:"short='D',help='UDP destination port',default='6666'"`
	Payload   string `kong:"short='p',help='UDP payload',default='this is my payload datas'"`
	ZeroLen   bool   `kong:"short='z',help='Pass 0 as the length to the kernel'"`
}

var log *logrus.Logger

func main() {
	var err error
	log = logrus.New()
	cli := CLI{}
	parser := kong.Must(
		&cli,
		kong.UsageOnError(),
		kong.Vars{},
	)
	_, err = parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	if os.Getuid() != 0 {
		log.Fatalf("must run rawsocktest as root")
	}

	ulen := []byte{0, 0}
	binary.BigEndian.PutUint16(ulen, uint16(len(cli.Payload)))
	payload := gopacket.Payload([]byte(cli.Payload))
	udp := &rawlayers.UDP{
		SrcPort:  layers.UDPPort(cli.SrcPort),
		DstPort:  layers.UDPPort(cli.DstPort),
		Length:   0x20, // binary.BigEndian.Uint16(ulen), // calculated
		Checksum: 0,    // calculated
	}

	srcIP := net.ParseIP(cli.SrcIP)
	dstIP := net.ParseIP(cli.DstIP)
	fmt.Printf("%s:%d -> %s:%d\n", cli.SrcIP, cli.SrcPort, cli.DstIP, cli.DstPort)

	ip4 := &rawlayers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0, // calculated
		Id:         0x1234,
		Flags:      0,
		FragOffset: 0,
		TTL:        10,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0, // calculated
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	udp.SetNetworkLayerForChecksum(ip4)

	opts := gopacket.SerializeOptions{
		FixLengths:       !cli.ZeroLen,
		ComputeChecksums: true,
	}

	buffer := gopacket.NewSerializeBuffer()
	if err = gopacket.SerializeLayers(buffer, opts, ip4, udp, payload); err != nil {
		log.WithError(err).Fatalf("unable to serialize")
	}
	b := buffer.Bytes()
	printPacket(b)

	var s int
	// open socket
	if s, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW); err != nil {
		log.WithError(err).Fatalf("unable to open socket")
	}

	/*
	 * cli.BufSize < 0: auto-calculate based on packet size
	 * cli.BufSize == 0: do not set SO_SNDBUF at all
	 * cli.BufSize > 0: explicitly set SO_SNDBUF size
	 */
	bufLen := len(b)
	if cli.BufSize > -1 {
		bufLen = cli.BufSize
	}
	if bufLen != 0 {
		log.Infof("Setting SO_SNDBUF to %d bytes", bufLen)

		// set send buffer size
		if err = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufLen); err != nil {
			log.WithError(err).Fatalf("unable to SNDBUF")
		}
	}

	// we will provide the IP header
	if err = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		log.WithError(err).Fatalf("unable to IP_HDRINCL")
	}

	// bypass routing table?
	if cli.NoRoute {
		if err = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_DONTROUTE, 1); err != nil {
			log.WithError(err).Fatalf("unable to DONTROUTE")
		}
	}

	// bind to a specific interface?
	if cli.Interface != "" {
		iface, err := net.InterfaceByName(cli.Interface)
		if err != nil {
			log.WithError(err).Fatalf("unable to lookup %s", cli.Interface)
		}

		bind_device(s, iface)
	}

	syscall.Setgid(syscall.Getgid())
	syscall.Setuid(syscall.Getuid())

	// send it!
	addr := syscall.SockaddrInet4{
		// Family: AF_INET is hard coded
		Addr: [4]byte{dstIP.To4()[0], dstIP.To4()[1], dstIP.To4()[2], dstIP.To4()[3]},
	}
	for i := 0; i < cli.Count; i++ {
		// err = syscall.Sendto(s, b, 0, &addr)
		bufLen, err = syscall.SendmsgN(s, b, []byte{}, &addr, 0)
		if err != nil {
			log.WithError(err).Fatalf("sendto")
		}

		log.Infof("Sent %d bytes to %s:%d", bufLen, cli.DstIP, cli.DstPort)
	}
	syscall.Close(s)
}

func printPacket(b []byte) {
	first := true
	for cIdx, c := range b {
		if cIdx%16 == 0 {
			if !first {
				fmt.Printf("\n\t")
			} else {
				fmt.Printf("\t")
			}
			first = false
		} else if cIdx%2 == 0 {
			fmt.Printf(" ")
		}
		fmt.Printf("%02x", c)
	}
	fmt.Printf("\n")
}
