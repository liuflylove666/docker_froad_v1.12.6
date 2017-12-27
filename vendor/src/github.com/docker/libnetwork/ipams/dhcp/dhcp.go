package dhcp

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/d2g/dhcp4"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/ipamapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/types"
)

const (
	localAddressSpace  = "LocalDefault"
	globalAddressSpace = "GlobalDefault"
	dhcpDriverName     = "dhcp"
	dhcpPrefix         = "dhcp"
	dhcpSrvrOpt        = "server"                         // used for --ipam-opt server
	dhcpInterface      = "dhcp_interface"                 // used for --ipam-opt dhcp_interface
	dsConfigKey        = "ipam/" + dhcpPrefix + "/config" // datastore keyes for ipam objects
	dsDataKey          = "ipam/" + dhcpPrefix + "/data"
)

// Allocator provides per address space ipv4/ipv6 book keeping
type Allocator struct {
	addrSpaces map[string]*addrSpace
	sync.Mutex
}
type dhcpLease struct {
	mac           net.HardwareAddr
	leaseIP       *net.IPNet
	gateway       *net.IPNet
	dpacket       *dhcp4.Packet
	parent        string
	preferredAddr bool
}

type dhcpPool struct {
	ID               string
	DhcpServer       net.IP
	IPv4Subnet       *net.IPNet
	Gateway          *net.IPNet
	DhcpInterface    string
	CreatedSlaveLink bool
	dhcpLeases       map[string]*dhcpLease
	dbIndex          uint64
	dbExists         bool
	sync.Mutex
}

// Init registers the built-in ipam service with libnetwork
func Init(ic ipamapi.Callback, l, g interface{}) error {
	var (
		ok                bool
		localDs, globalDs datastore.DataStore
	)

	if l != nil {
		if localDs, ok = l.(datastore.DataStore); !ok {
			return fmt.Errorf("incorrect local datastore passed to dhcpPool init")
		}
	}

	if g != nil {
		if globalDs, ok = g.(datastore.DataStore); !ok {
			return fmt.Errorf("incorrect global datastore passed to dhcpPool init")
		}
	}
	a, err := NewAllocator(localDs, globalDs)
	if err != nil {
		return err
	}

	cps := &ipamapi.Capability{RequiresMACAddress: true}

	return ic.RegisterIpamDriverWithCapabilities(dhcpDriverName, a, cps)
}

// NewAllocator returns an instance of libnetwork ipam
func NewAllocator(lcDs, glDs datastore.DataStore) (*Allocator, error) {
	a := &Allocator{}
	// Initialize address spaces
	a.addrSpaces = make(map[string]*addrSpace)
	for _, aspc := range []struct {
		as string
		ds datastore.DataStore
	}{
		{localAddressSpace, lcDs},
		{globalAddressSpace, glDs},
	} {
		a.initializeAddressSpace(aspc.as, aspc.ds)
	}

	return a, nil
}

func (a *Allocator) refresh(as string) error {
	aSpace, err := a.getAddressSpaceFromStore(as)
	if err != nil {
		return types.InternalErrorf("error getting pools config from store: %v", err)
	}
	if aSpace == nil {
		return nil
	}
	a.Lock()
	a.addrSpaces[as] = aSpace
	for _, v := range aSpace.dhcpPools {
		v.dhcpLeases = make(map[string]*dhcpLease)
	}
	a.Unlock()
	return nil
}

// Checks for and fixes damaged bitmask.
func (a *Allocator) checkConsistency(as string) {
	// Retrieve this address space's configuration and bitmasks from the datastore
	a.refresh(as)
}

func (a *Allocator) initializeAddressSpace(as string, ds datastore.DataStore) error {
	scope := ""
	if ds != nil {
		scope = ds.Scope()
	}

	a.Lock()
	if currAS, ok := a.addrSpaces[as]; ok {
		if currAS.ds != nil {
			a.Unlock()
			return types.ForbiddenErrorf("a datastore is already configured for the address space %s", as)
		}
	}
	a.addrSpaces[as] = &addrSpace{
		dhcpPools: make(map[string]*dhcpPool),
		id:        dsConfigKey + "/" + as,
		scope:     scope,
		ds:        ds,
		alloc:     a,
	}

	a.Unlock()

	a.checkConsistency(as)

	return nil
}

// DiscoverNew informs the allocator about a new global scope datastore
func (a *Allocator) DiscoverNew(dType discoverapi.DiscoveryType, data interface{}) error {
	if dType != discoverapi.DatastoreConfig {
		return nil
	}

	dsc, ok := data.(discoverapi.DatastoreConfigData)
	if !ok {
		return types.InternalErrorf("incorrect data in datastore update notification: %v", data)
	}

	ds, err := datastore.NewDataStoreFromConfig(dsc)
	if err != nil {
		return err
	}

	return a.initializeAddressSpace(globalAddressSpace, ds)
}

// DiscoverDelete is a notification of no interest for the allocator
func (a *Allocator) DiscoverDelete(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}

// GetDefaultAddressSpaces returns the local and global default address spaces
func (a *Allocator) GetDefaultAddressSpaces() (string, string, error) {
	return localAddressSpace, globalAddressSpace, nil
}

func (a *Allocator) buildId(addressSpace, ipStr string) string {
	return addressSpace + "/" + ipStr
}

func (a *Allocator) GetAddressSpace(poolId string) string {
	p := strings.Split(poolId, "/")
	return p[0]
}
func GetRealPoolId(poolId string) string {
	p := strings.Split(poolId, "/")
	return strings.Join(p[1:], "/")
}

// RequestPool will attempt to discover a subnet for the pool with a DHCP discover
func (a *Allocator) RequestPool(addressSpace, pool, subPool string, options map[string]string, v6 bool) (string, *net.IPNet, map[string]string, error) {
	logrus.Debugf("RequestPool(addressSpace: %s, pool: %s, subPool: %s, options: %v)", addressSpace, pool, subPool, options)
	dp := &dhcpPool{
		dhcpLeases: make(map[string]*dhcpLease),
	}
	if subPool != "" || v6 {
		return "", nil, nil, fmt.Errorf("This request is not supported by the DHCP ipam driver")
	}
	for option, value := range options {
		switch option {
		case dhcpSrvrOpt:
			// parse DHCP server option '--ipam-opt server=x.x.x.x'
			if ok := isIPv4(value); !ok {
				// check for a resolvable DNS if not an IP
				resolvedIP, err := nameLookup(value)
				if err != nil {
					return "", nil, nil, fmt.Errorf("the specified DHCP server %s is neither an IPv4 address nor a resolvable DNS address", value)
				}
				dp.DhcpServer = resolvedIP
			} else {
				dp.DhcpServer = net.ParseIP(value)
			}
		case dhcpInterface:
			// parse DHCP interface option '--ipam-opt dhcp_interface=eth0'
			dp.DhcpInterface = value
			if !parentExists(dp.DhcpInterface) {
				if pool == "" {
					return "", nil, nil, fmt.Errorf("Spanning-Tree convergence can block forwarding and thus DHCP for up to 50 seconds. If creating VLAN subinterfaces, --gateway and --subnet are required in 'docker network create'.")
				}
				// if the subinterface parent_iface.vlan_id checks do not pass, return err.
				//  a valid example is 'eth0.10' for a parent iface 'eth0' with a vlan id '10'
				err := createVlanLink(dp.DhcpInterface)
				if err != nil {
					return "", nil, nil, fmt.Errorf("failed to create the %s subinterface: %v", value, err)
				}
				dp.CreatedSlaveLink = true
			}
		}
	}
	// require an interface to send DHCP discover and requests
	if dp.DhcpInterface == "" {
		return "", nil, nil, fmt.Errorf("required DHCP IPAM option -ipam-opt dhcp_interface= to specify which interface to send a DHCP request not found")
	}
	// if the --subnet is specified, skip DHCP DISCOVER attempts
	if pool != "" {
		_, poolNet, err := net.ParseCIDR(pool)
		if err != nil {
			return "", nil, nil, err
		}
		// sanity check user specified netmasks for /0 or /32 networks
		if poolNet.Mask.String() == "ffffffff" || poolNet.Mask.String() == "00000000" {
			return "", nil, nil, fmt.Errorf("Invalid specified pool netmasks /0 or /32 not allowed")
		}
		dp.IPv4Subnet = poolNet
		dp.ID = a.buildId(addressSpace, dp.IPv4Subnet.String())
		logrus.Debugf("Creating DHCP Discovered Network: %v, Gateway: %v", dp.IPv4Subnet, dp.Gateway)
		a.addPool(dp, addressSpace)
		addrSpace := a.addrSpaces[addressSpace]
		// update persistent cache for host reboots or engine restarts
		err = a.writeToStore(addrSpace)
		if err != nil {
			logrus.Errorf("adding DHCP Pool to datastore failed: %v", err)
		}
		// update persistent cache for host reboots or engine restarts
		//return dp.IPv4Subnet.String(), dp.IPv4Subnet, options, nil
		return a.buildId(addressSpace, dp.IPv4Subnet.String()), dp.IPv4Subnet, options, nil
	} else {
		// Probe with a DHCP DISCOVER packet for the network
		err := dp.dhcpDiscoverPool()
		if err != nil {
			// on DHCP Discover failure rollback the subinterface if one was created
			if dp.CreatedSlaveLink && parentExists(dp.DhcpInterface) {
				// TODO: remove this block if discover on subint creation is not permitted
				err := delVlanLink(dp.DhcpInterface)
				if err != nil {
					logrus.Debugf("link %s was not deleted, continuing the pool request subinterface rollback: %v", dp.DhcpInterface, err)
				}
			}
			logrus.Error("Unable to find a DHCP service on the parent interface")
			return "", nil, nil, err
		}
		// Set the gateway label from the DHCP provided gateway
		options[netlabel.Gateway] = dp.Gateway.String()
		// Parse the network address from the DHCP Probe
		_, netCidr, err := net.ParseCIDR(dp.IPv4Subnet.String())
		if err != nil {
			return "", nil, nil, err
		}
		//dp.ID = dp.IPv4Subnet.String()
		dp.ID = a.buildId(addressSpace, dp.IPv4Subnet.String())
		logrus.Debugf("Creating DHCP Discovered Network: %v, Gateway: %v", netCidr, dp.Gateway)
		a.addPool(dp, addressSpace)
		addrSpace := a.addrSpaces[addressSpace]
		// update persistent cache for host reboots or engine restarts
		err = a.writeToStore(addrSpace)
		if err != nil {
			logrus.Errorf("adding DHCP Pool to datastore failed: %v", err)
		}

		//return dp.IPv4Subnet.String(), netCidr, options, nil
		return a.buildId(addressSpace, dp.IPv4Subnet.String()), netCidr, options, nil
		}
}

// ReleasePool releases the address pool - always succeeds
func (a *Allocator) ReleasePool(poolID string) error {
	addressSpace := a.GetAddressSpace(poolID)
	dp, err := a.getPool(poolID, addressSpace)
	if err != nil {
		logrus.Debugf("Pool ID %s not found", poolID)
		return nil
	}
	// if the driver created the slave interface, delete it, otherwise leave it
	if ok := dp.CreatedSlaveLink; ok {
		// if the interface exists, only delete if it matches iface.vlan or dummy.net_id naming
		if ok := parentExists(dp.DhcpInterface); ok {
			// only delete the link if it is named the net_id
			// only delete the link if it matches iface.vlan naming
			err := delVlanLink(dp.DhcpInterface)
			if err != nil {
				logrus.Debugf("link %s was not deleted, continuing the release pool operation: %v",
					dp.DhcpInterface, err)
			}
		}
	}
	a.deletePool(poolID, addressSpace)
	addrSpace := a.addrSpaces[addressSpace]
	// remove the pool from persistent k/v store
	a.writeToStore(addrSpace)
	logrus.Debugf("Releasing DHCP pool %s)", poolID)

	return nil
}

// Given the address space, returns the local or global PoolConfig based on the
// address space is local or global. AddressSpace locality is being registered with IPAM out of band.
func (a *Allocator) getAddrSpace(as string) (*addrSpace, error) {
	a.Lock()
	defer a.Unlock()
	aSpace, ok := a.addrSpaces[as]
	if !ok {
		return nil, types.BadRequestErrorf("cannot find address space %s (most likely the backing datastore is not configured)", as)
	}
	return aSpace, nil
}

// RequestAddress calls the ipam driver for an IP address for a create endpoint event
func (a *Allocator) RequestAddress(poolID string, prefAddress net.IP, opts map[string]string) (*net.IPNet, map[string]string, error) {
	logrus.Debugf("Received Address Request Pool ID: %s, Preffered Address: %v, Options: %v", poolID, prefAddress, opts)
	addressSpace := a.GetAddressSpace(poolID)

	poolNetAddr, PoolNet, err := net.ParseCIDR(GetRealPoolId(poolID))
	if err != nil {
		return nil, nil, err
	}
	// lookup the pool id and verify it exists
	n, err := a.getPool(poolID, addressSpace)
	if err != nil {
		return nil, nil, fmt.Errorf("pool ID %s not found", poolID)
	}
	// if the network create includes --subnet & --gateway the gateway will be passed as preAddress
	if opts[ipamapi.RequestAddressType] == netlabel.Gateway && prefAddress != nil {
		// append the pool v4 subnet netmask to the gateway to create a proper cidr
		n.Gateway = &net.IPNet{
			IP:   prefAddress,
			Mask: n.IPv4Subnet.Mask,
		}
		// return the requested gateway label
		return n.Gateway, nil, nil
	}
	// if the network create includes --subnet but not --gateway, infer a gateway
	if opts[ipamapi.RequestAddressType] == netlabel.Gateway {
		n.Gateway = inferGateway(poolNetAddr, PoolNet)
		logrus.Infof("no --gateway= was passed, infering a gateway of %s for the user specified --network=%s",
			n.Gateway.IP.String(), n.IPv4Subnet.String())
		// return the requested gateway label
		return n.Gateway, nil, nil
	}
	// parse the mac address that is sent due to ipam capability
	macAddr := opts[netlabel.MacAddress]
	if len(macAddr) <= 0 {
		return PoolNet, nil, fmt.Errorf("no mac address found in the request address call")
	}
	// Preferred addresses w/DHCP driver currently rejected by libnetwork since --subnet not passed by user
	if prefAddress != nil {
		staticAddr, err := a.preferredAddrHandler(prefAddress, PoolNet)
		if err != nil {
			return nil, nil, err
		}
		// return the static preferred address
		return staticAddr.leaseIP, nil, nil
	}
	// Request a DHCP lease from the DHCP server
	lease, err := requestDHCPLease(macAddr, n.DhcpInterface)
	if err != nil {
		logrus.Debugf("requestDHCPLease=%v", err)
		// fail the request if a DHCP lease is unavailable
		return nil, nil, err
	}
	// verify the DHCP lease falls within the network pool. If the DHCP network has changed,
	// the discovered pool and network will be invalid and the network will need to be recreated.
	if ok := netContains(lease.leaseIP.IP, n.IPv4Subnet); !ok {
		logrus.Debugf("netContains=%v\n", lease)
		return nil, nil, fmt.Errorf("the DHCP assigned address %s is not valid in the pool network %s If the DHCP network has changed, recreate the network for new discovery",
			lease.leaseIP.IP.String(), n.IPv4Subnet.String())
	}
	logrus.Debugf("DHCP request returned a lease of IP: %v, Gateway: %v", lease.leaseIP, lease.gateway)
	// bind the lease to the lease table and store ack details for a dhcp release
	n.addLease(lease)
	// leases are not stored in persistent datastore, ony pools are stored.
	return lease.leaseIP, nil, nil
}

// ReleaseAddress releases the address - always succeeds
func (a *Allocator) ReleaseAddress(poolID string, address net.IP) error {
	addressSpace := a.GetAddressSpace(poolID)
	logrus.Debugf("Release DHCP address Pool ID: %s Address: %v", poolID, address)
	// lookup the pool the lease is stored in
	n, err := a.getPool(poolID, addressSpace)
	if err != nil {
		logrus.Errorf("Pool ID %s not found", poolID)
		return nil
	}
	if n.Gateway != nil {
		// if the address to release is the gateway ignore it
		if n.Gateway.IP != nil {
			if address.String() == n.Gateway.IP.String() {
				logrus.Debugf("Release request is for a gateway address, no DHCP release required")
				return nil
			}
		}
	}
	// construct cidr address+mask for lease key
	leaseID := &net.IPNet{
		IP:   address,
		Mask: n.IPv4Subnet.Mask,
	}
	// get the lease to send the dhcp ack in the release
	l, err := n.getLease(leaseID.String())
	if l == nil || l.preferredAddr {
		return nil
	}
	l.release()
	n.deleteLease(leaseID.String())
	return nil
}
func (a *Allocator) preferredAddrHandler(prefAddress net.IP, pool *net.IPNet) (*dhcpLease, error) {
	// set preferred address so as not to attempt a DHCP release
	l := &dhcpLease{
		preferredAddr: true,
	}
	// set the preferred IP address rather then a DHCP address
	l.leaseIP = &net.IPNet{
		IP:   prefAddress,
		Mask: pool.Mask,
	}
	// verify the preferred address is a valid address in the requested pool
	if ok := netContains(l.leaseIP.IP, pool); !ok {
		return nil, fmt.Errorf("the requested IP address %s is not valid in the pool network %s If the DHCP network has changed, recreate the network for new discovery",
			l.leaseIP.IP.String(), pool.String())
	}

	return l, nil
}
