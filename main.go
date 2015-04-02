package main

/*
 *    SprayTrace
 *    sniff packets whilest spraying packet.
 *    increment ip ttl between each burst of packets.
 *
 *    written by David for Leif and Aaron
 *
 *    todo:
 *     - make TCP header flags user configurable
 *     - make ipv6 compatible?
 *
 *
 *    Copyright (C) 2014  David Stainton
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
	"log"
	"net"
)

// PacketSprayerOptions are user specified parameters that
// control the behavior of PacketSprayer.
type PacketSprayerOptions struct {
	NetInterface string
}

// PacketSprayer handles the business of sending out a packet one or more times.
type PacketSprayer struct {
	PacketSprayerOptions
	packetConn    net.PacketConn
	rawConn       *ipv4.RawConn
	ipHeader      *ipv4.Header
	ip            layers.IPv4
	tcp           layers.TCP
	ipBuf         gopacket.SerializeBuffer
	tcpPayloadBuf gopacket.SerializeBuffer
	payload       gopacket.Payload
}

func NewPacketSprayer(options PacketSprayerOptions) *PacketSprayer {
	return &PacketSprayer{
		PacketSprayerOptions: options,
	}
}

func (p *PacketSprayer) Start() {
	var err error
	p.packetConn, err = net.ListenPacket("ip4:tcp", p.NetInterface)
	if err != nil {
		panic(err)
	}
}

func (p *PacketSprayer) SetIPLayer(iplayer layers.IPv4) error {
	p.ip = iplayer
	p.ipBuf = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := p.ip.SerializeTo(p.ipBuf, opts)
	if err != nil {
		return err
	}
	p.ipHeader, err = ipv4.ParseHeader(p.ipBuf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (p *PacketSprayer) SetTCPLayer(tcpLayer layers.TCP) {
	p.tcp = tcpLayer
}

func (p *PacketSprayer) SetPayload(payload []byte) {
	p.payload = payload
}

func (p *PacketSprayer) Spray(count int) error {
	var err error
	p.tcp.SetNetworkLayerForChecksum(&p.ip)
	p.tcpPayloadBuf = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(p.tcpPayloadBuf, opts, &p.tcp, p.payload)
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = p.Send()
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PacketSprayer) Send() error {
	err := p.rawConn.WriteTo(p.ipHeader, p.tcpPayloadBuf.Bytes(), nil)
	return err
}

// TcpIpFlow is used for tracking unidirectional TCP flows
type TcpIpFlow struct {
	ipFlow  gopacket.Flow
	tcpFlow gopacket.Flow
}

// NewTcpIpFlowFromLayers given IPv4 and TCP layers it returns a TcpIpFlow
func NewTcpIpFlowFromLayers(ipLayer layers.IPv4, tcpLayer layers.TCP) *TcpIpFlow {
	return &TcpIpFlow{
		ipFlow:  ipLayer.NetworkFlow(),
		tcpFlow: tcpLayer.TransportFlow(),
	}
}

// String returns the string representation of a TcpIpFlow
func (t TcpIpFlow) String() string {
	return fmt.Sprintf("%s:%s->%s:%s", t.ipFlow.Src().String(), t.tcpFlow.Src().String(), t.ipFlow.Dst().String(), t.tcpFlow.Dst().String())
}

type SloppyTraceOptions struct {
	Interface   string
	Snaplen     int
	CollectBPF  string
	PacketCount int
	StartTtl    uint8
	EndTtl      uint8
	DstIP       net.IP
	DstPort     uint32
	SrcIP       net.IP
	SrcPort     uint32
	Payload     []byte
}

type SloppyTrace struct {
	SloppyTraceOptions
	sprayer *PacketSprayer
}

func NewSloppyTrace(options *SloppyTraceOptions) *SloppyTrace {
	s := SloppyTrace{
		SloppyTraceOptions: *options,
	}
	sprayOptions := PacketSprayerOptions{
		NetInterface: options.Interface,
	}
	s.sprayer = NewPacketSprayer(sprayOptions)
	return &s
}

func (s *SloppyTrace) Start() {
	log.Print("start of SloppyTrace")

	s.sprayer.Start()

	// XXX todo synchronize them...
	go s.SendProbes()
	s.CollectProbes()

	log.Print("end of SloppyTrace")
}

// PrepareLayerCake prepares a delicious and fluffy protocol layer cake suitable for hackers.
func (s *SloppyTrace) PrepareLayerCake() (*layers.IPv4, *layers.TCP) {
	ipLayer := layers.IPv4{
		SrcIP:    s.SrcIP,
		DstIP:    s.DstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(s.SrcPort),
		DstPort: layers.TCPPort(s.DstPort),

		// XXX todo: make configurable
		ACK: true,
		PSH: true,
	}
	return &ipLayer, &tcpLayer
}

func (s *SloppyTrace) SendProbes() {
	var err error

	log.Print("starting to send probes.")

	ip, tcp := s.PrepareLayerCake()
	s.sprayer.SetTCPLayer(*tcp)

	for i := s.StartTtl; i < s.EndTtl; i++ {
		ip.TTL = uint8(i)
		s.sprayer.SetIPLayer(*ip)
		if err != nil {
			panic(err)
		}

		err = s.sprayer.Spray(s.PacketCount)
		if err != nil {
			panic(err)
		}
	}

	log.Print("probe sending complete.")
}

func (s *SloppyTrace) CollectProbes() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	log.Print("probe collection started")

	handle, err := pcap.OpenLive(s.Interface, int32(s.Snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err = handle.SetBPFFilter(s.CollectBPF); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ip, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	for {
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Printf("error getting packet: %v %s", err, ci)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("error decoding packet: %v", err)
			continue
		}

		flow := NewTcpIpFlowFromLayers(ip, tcp)
		log.Printf("packet flow %s\n", flow)
		log.Printf("IP TTL %d\n", ip.TTL)
	}

	// XXX
	log.Print("probe collection neverending?")
}

func main() {
	var (
		iface   = flag.String("interface", "eth0", "network interface used to send and receive packets")
		snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
		filter  = flag.String("f", "tcp", "BPF for sniffing")

		packetCount = flag.Int("packetCount", 123, "number of packets to send for each ttl")
		startTtl    = flag.Int("startTTL", 30, "starting TTL that will be used in the traceroute")
		endTtl      = flag.Int("endTTL", 30, "ending TTL that will be used in the traceroute")

		dstIPstr = flag.String("dstIP", "", "destination ip address")
		dstPort  = flag.Int("dstPort", 12345, "destination tcp port")
		srcIPstr = flag.String("srcIP", "", "source ip address")
		srcPort  = flag.Int("srcPort", 12345, "source tcp port")

		// XXX fix me
		//payload = flag.String("payload", "", "packet payload")
	)

	flag.Parse()

	dstIP := net.ParseIP(*dstIPstr)
	if dstIP == nil {
		panic(fmt.Sprintf("non-ip target: %q\n", dstIPstr))
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		panic(fmt.Sprintf("non-ipv4 target: %q\n", dstIPstr))
	}

	srcIP := net.ParseIP(*srcIPstr)
	if srcIP == nil {
		panic(fmt.Sprintf("non-ip target: %q\n", srcIPstr))
	}
	srcIP = srcIP.To4()
	if srcIP == nil {
		panic(fmt.Sprintf("non-ipv4 target: %q\n", srcIPstr))
	}

	options := SloppyTraceOptions{
		Interface:  *iface,
		Snaplen:    *snaplen,
		CollectBPF: *filter,

		DstIP:   dstIP,
		DstPort: uint32(*dstPort),
		SrcIP:   srcIP,
		SrcPort: uint32(*srcPort),

		PacketCount: *packetCount,
		StartTtl:    uint8(*startTtl),
		EndTtl:      uint8(*endTtl),

		Payload: []byte("GET /TPS_report.js HTTP/1.1\r\nHost: badAttackerHost.com\r\nAccept: */*\r\n\r\n"),
	}
	trace := NewSloppyTrace(&options)
	trace.Start()
}
