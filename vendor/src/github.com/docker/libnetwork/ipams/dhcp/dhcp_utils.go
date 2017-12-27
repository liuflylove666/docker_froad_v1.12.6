package dhcp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4client"
	"github.com/vishvananda/netlink"
)

var dummyMacAddr = net.HardwareAddr([]byte{02, 17, 17, 17, 17, 17}) // used for DHCP DISCOVER

// requestDHCPLease creates a DHCP REQUEST for a new IP address lease for a container
func requestDHCPLease(macaddr, parent string) (*dhcpLease, error) {
	hwaddr, err := net.ParseMAC(macaddr)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse a valid mac address from %s: %v", macaddr, err)
	}
	l := &dhcpLease{
		mac:    hwaddr,
		parent: parent,
	}
	link, err := netlink.LinkByName(l.parent)
	if err != nil {
		return nil, err
	}
	client, err := dhcpSocket(l.mac, link)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err != nil {
		return nil, fmt.Errorf("unable to create a DHCP client request: ")
	}
	ok, ack, err := client.Request()
	if !ok || err != nil {
		// replacing the dhcp4 library message of "resource temporarily unavailable" with a more informative one
		return nil, fmt.Errorf("DHCP discovery failed, ensure interface %s is in promiscous mode and an active DHCP server is available",
			link.Attrs().Name)
	}
	if err != nil {
		networkError := err.(*net.OpError)
		if ok && networkError.Timeout() {
			return nil, fmt.Errorf("Cannot find DHCP server: %v", networkError)
		}
	}
	opts := ack.ParseOptions()
	if ack == nil {
		return nil, fmt.Errorf("Null or unhandled DHCP response")
	}
	l.dpacket = &ack
	netmask := getNetMask(opts)
	// ensure the required fields are not null
	if netmask == nil || l.dpacket.YIAddr() == nil {
		return nil, fmt.Errorf("invalid DHCP configuration, network and gateway must not be empty")
	}
	// set the DHCP lease network configuration
	l.leaseIP = &net.IPNet{
		IP:   l.dpacket.YIAddr(),
		Mask: netmask,
	}

	return l, nil
}

// dhcpSocket builds the dhcp4client using the user specified dhcp_interface= link to send DHCP REQUESTS/DISCOVERS
func dhcpSocket(hwaddr net.HardwareAddr, link netlink.Link) (*dhcp4client.Client, error) {
	psock, err := dhcp4client.NewPacketSock(link.Attrs().Index)
	if err != nil {
		return nil, err
	}
	return dhcp4client.New(
		dhcp4client.HardwareAddr(hwaddr),
		dhcp4client.Broadcast(true),
		dhcp4client.Timeout(5*time.Second),
		dhcp4client.Connection(psock),
	)
}

// release the DHCP lease back to the DHCP server pool, the data from the request ACK are used
func (dl *dhcpLease) release() error {
	logrus.Infof("Releasing lease for container address %s", dl.leaseIP.IP.String())

	link, err := netlink.LinkByName(dl.parent)
	if err != nil {
		return err
	}
	c, err := dhcpSocket(dl.mac, link)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.Release(*dl.dpacket); err != nil {
		logrus.Debugf("failed to release the DHCP lease")
	}

	return nil
}

// dhcpDiscoverPool sends a DHCP DISCOVER out the user specified dhcp_interface= link to discover the network pool
func (dp *dhcpPool) dhcpDiscoverPool() error {
	link, err := netlink.LinkByName(dp.DhcpInterface)
	if err != nil {
		return err
	}
	// use the parent interface MAC address for DHCP pool discovery
	client, err := dhcpSocket(dummyMacAddr, link)
	if err != nil {
		return err
	}
	defer client.Close()
	if err != nil {
		return fmt.Errorf("Unable to create a DHCP client request: %v", err)
	}
	disc, err := client.SendDiscoverPacket()
	if err != nil {
		return fmt.Errorf("DHCP discover failed, ensure there is a DHCP server running on requested segment: %v", err)
	}
	if disc == nil {
		return fmt.Errorf("Null or unhandled DHCP discover response")
	}
	discovered, err := client.GetOffer(&disc)
	if err != nil {
		// replacing the dhcp4 library message of "resource temporarily unavailable" with a more informative one
		return fmt.Errorf("DHCP discovery failed, ensure interface %s is in promiscous mode and an active DHCP server is available",
			link.Attrs().Name)
	}
	// parse and bind the results of the discovery offer
	opts := discovered.ParseOptions()
	gw4 := getGateway(opts)
	netmask := getNetMask(opts)
	dp.DhcpServer = getDhcpServer(opts)
	// ensure the required fields are not null
	if gw4 == nil || netmask == nil || discovered.YIAddr() == nil {
		return fmt.Errorf("invalid DHCP configuration, network and gateway must not be empty")
	}
	dp.IPv4Subnet = &net.IPNet{
		IP:   discovered.YIAddr(),
		Mask: netmask,
	}
	// parse the network CIDR the net pool to ensure a proper CIDR net is returned
	_, dp.IPv4Subnet, err = net.ParseCIDR(dp.IPv4Subnet.String())
	if err != nil {
		return err
	}
	// set the DHCP pool gateway configuration
	dp.Gateway = &net.IPNet{
		IP:   gw4,
		Mask: netmask,
	}
	logrus.Debugf("DHCP discovered network IP: %s, Gateway: %s", dp.IPv4Subnet.String(), dp.Gateway.String())

	return nil
}

// getSubnet decodes net.IPMask from dhcp op code1
func getNetMask(opts dhcp4.Options) net.IPMask {
	if opts, ok := opts[dhcp4.OptionSubnetMask]; ok {
		return net.IPMask(opts)
	}

	return nil
}

// getSubnet decodes net.IP from dhcp op code3
func getGateway(opts dhcp4.Options) net.IP {
	if opts, ok := opts[dhcp4.OptionRouter]; ok {
		if len(opts) == 4 {
			return net.IP(opts)
		}
	}

	return nil
}

// getDhcpServer decodes net.IP from dhcp op code54 representing the DHCP server id/src_ip
func getDhcpServer(opts dhcp4.Options) net.IP {
	if opts, ok := opts[dhcp4.OptionServerIdentifier]; ok {
		return net.IP(opts)
	}

	return nil
}

// createVlanLink parses sub-interfaces and vlan id for creation
func createVlanLink(parentName string) error {
	if strings.Contains(parentName, ".") {
		parent, vidInt, err := parseVlan(parentName)
		if err != nil {
			return err
		}
		// VLAN identifier or VID is a 12-bit field specifying the VLAN to which the frame belongs
		if vidInt > 4094 || vidInt < 1 {
			return fmt.Errorf("vlan id must be between 1-4094, received: %d", vidInt)
		}
		// get the parent link to attach a vlan subinterface
		parentLink, err := netlink.LinkByName(parent)
		if err != nil {
			return fmt.Errorf("failed to find master interface %s on the Docker host: %v", parent, err)
		}
		vlanLink := &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        parentName,
				ParentIndex: parentLink.Attrs().Index,
			},
			VlanId: vidInt,
		}
		// create the subinterface
		if err := netlink.LinkAdd(vlanLink); err != nil {
			return fmt.Errorf("failed to create %s vlan link: %v", vlanLink.Name, err)
		}
		// Bring the new netlink iface up
		if err := netlink.LinkSetUp(vlanLink); err != nil {
			return fmt.Errorf("failed to enable %s the dhcp interface link %v", vlanLink.Name, err)
		}
		logrus.Debugf("Added a vlan tagged netlink subinterface: %s with a vlan id: %d", parentName, vidInt)
		return nil
	}

	return fmt.Errorf("invalid subinterface vlan name %s, example formatting is eth0.10", parentName)
}

// delVlanLink verifies only sub-interfaces with a vlan id get deleted
func delVlanLink(linkName string) error {
	if strings.Contains(linkName, ".") {
		_, _, err := parseVlan(linkName)
		if err != nil {
			return err
		}
		// delete the vlan subinterface
		vlanLink, err := netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("failed to find interface %s on the Docker host : %v", linkName, err)
		}
		// verify a parent interface isn't being deleted
		if vlanLink.Attrs().ParentIndex == 0 {
			return fmt.Errorf("interface %s does not appear to be a slave device: %v", linkName, err)
		}
		// delete the dhcp vlan interface slave device
		if err := netlink.LinkDel(vlanLink); err != nil {
			return fmt.Errorf("failed to delete  %s link: %v", linkName, err)
		}
		logrus.Debugf("Deleted a vlan tagged netlink subinterface: %s", linkName)
	}
	// if the subinterface doesn't parse to iface.vlan_id leave the interface in
	// place since it could be a user specified name not created by the driver.
	return nil
}

// parseVlan parses and verifies a slave interface name: -o parent=eth0.10
func parseVlan(linkName string) (string, int, error) {
	// parse -o parent=eth0.10
	splitName := strings.Split(linkName, ".")
	if len(splitName) != 2 {
		return "", 0, fmt.Errorf("required interface name format is: name.vlan_id, ex. eth0.10 for vlan 10, instead received %s", linkName)
	}
	parent, vidStr := splitName[0], splitName[1]
	// validate type and convert vlan id to int
	vidInt, err := strconv.Atoi(vidStr)
	if err != nil {
		return "", 0, fmt.Errorf("unable to parse a valid vlan id from: %s (ex. eth0.10 for vlan 10)", vidStr)
	}
	// Check if the interface exists
	if !parentExists(parent) {
		return "", 0, fmt.Errorf("-o parent interface does was not found on the host: %s", parent)
	}

	return parent, vidInt, nil
}

// parentExists check if the specified interface exists in the default namespace
func parentExists(ifaceStr string) bool {
	_, err := netlink.LinkByName(ifaceStr)
	if err != nil {
		return false
	}

	return true
}

// nameLookup attempts to resolve a name to IP
func nameLookup(s string) (net.IP, error) {
	ipAddr, err := net.ResolveIPAddr("ip", s)

	return ipAddr.IP, err
}

// isIPv4 verifies the network is IPv4
func isIPv4(s string) bool {
	srvrAddr := net.ParseIP(s)

	return srvrAddr.To4() != nil
}

// ipGateway increments the next address to infer a usable gateway if not defined
func inferGateway(netAddr net.IP, poolNet *net.IPNet) *net.IPNet {
	for i := 15; i >= 0; i-- {
		b := netAddr[i]
		if b < 255 {
			netAddr[i] = b + 1
			for ii := i + 1; ii <= 15; ii++ {
				netAddr[ii] = 0
			}
			break
		}
	}
	return &net.IPNet{IP: netAddr, Mask: poolNet.Mask}
}

// netContains is used to verify the DHCP lease falls within the bounds of the pool
func netContains(addr net.IP, netPool *net.IPNet) bool {
	return netPool.Contains(addr)
}
