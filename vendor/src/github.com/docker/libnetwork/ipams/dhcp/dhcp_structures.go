package dhcp

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/types"
	"net"
	"sync"
)

// addrSpace contains the pool configurations for the address space
type addrSpace struct {
	dhcpPools map[string]*dhcpPool
	dbIndex   uint64
	dbExists  bool
	id        string
	scope     string
	ds        datastore.DataStore
	alloc     *Allocator
	sync.Mutex
}

// MarshalJSON returns the JSON encoding of the addrSpace object
func (aSpace *addrSpace) MarshalJSON() ([]byte, error) {
	aSpace.Lock()
	defer aSpace.Unlock()
	m := map[string]interface{}{
		"Scope": string(aSpace.scope),
	}
	if len(aSpace.dhcpPools) > 0 {
		// s := make(map[string]*dhcpPool)
		// for k, v := range  {
		// 	s[k] = v
		// }
		m["DhcpPools"] = aSpace.dhcpPools
	}
	return json.Marshal(m)
}

// UnmarshalJSON decodes data into the addrSpace object
func (aSpace *addrSpace) UnmarshalJSON(data []byte) error {
	aSpace.Lock()
	defer aSpace.Unlock()
	m := map[string]interface{}{}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}
	aSpace.scope = datastore.LocalScope
	s := m["Scope"].(string)
	if s == string(datastore.GlobalScope) {
		aSpace.scope = datastore.GlobalScope
	}
	if v, ok := m["DhcpPools"]; ok {
		logrus.Infof("DhcpPools=%+v\n", v)
		sb, _ := json.Marshal(v)
		var s map[string]*dhcpPool
		err := json.Unmarshal(sb, &s)
		if err != nil {
			return err
		}
		for k, v := range s {
			aSpace.dhcpPools[k] = v
		}
	}
	return nil
}

func (aSpace *addrSpace) CopyTo(o datastore.KVObject) error {
	aSpace.Lock()
	defer aSpace.Unlock()
	dstAspace := o.(*addrSpace)
	dstAspace.id = aSpace.id
	dstAspace.ds = aSpace.ds
	dstAspace.alloc = aSpace.alloc
	dstAspace.scope = aSpace.scope
	dstAspace.dbIndex = aSpace.dbIndex
	dstAspace.dbExists = aSpace.dbExists
	dstAspace.dhcpPools = make(map[string]*dhcpPool)
	for k, v := range aSpace.dhcpPools {
		dstAspace.dhcpPools[k] = &dhcpPool{}
		v.CopyTo(dstAspace.dhcpPools[k])
	}
	return nil
}

func (aSpace *addrSpace) New() datastore.KVObject {
	aSpace.Lock()
	defer aSpace.Unlock()
	return &addrSpace{
		id:    aSpace.id,
		ds:    aSpace.ds,
		alloc: aSpace.alloc,
		scope: aSpace.scope,
	}
}

func (aSpace *addrSpace) store() datastore.DataStore {
	aSpace.Lock()
	defer aSpace.Unlock()
	return aSpace.ds
}

func (config *dhcpPool) MarshalJSON() ([]byte, error) {
	nMap := make(map[string]interface{})
	nMap["ID"] = config.ID
	nMap["CreatedSlaveLink"] = config.CreatedSlaveLink
	nMap["DhcpInterface"] = config.DhcpInterface
	nMap["DhcpServer"] = config.DhcpServer.String()
	if config.Gateway != nil {
		nMap["Gateway"] = config.Gateway.String()
	}
	if config.IPv4Subnet != nil {
		nMap["IPv4Subnet"] = config.IPv4Subnet.String()
	}

	return json.Marshal(nMap)
}

func (config *dhcpPool) UnmarshalJSON(b []byte) error {
	var (
		err  error
		nMap map[string]interface{}
	)
	if err = json.Unmarshal(b, &nMap); err != nil {
		return err
	}
	config.ID = nMap["ID"].(string)
	config.CreatedSlaveLink = nMap["CreatedSlaveLink"].(bool)
	config.DhcpInterface = nMap["DhcpInterface"].(string)
	config.DhcpServer = net.ParseIP(nMap["DhcpServer"].(string))
	// handle scenarios where the gateway is not user defined and thus null
	//if config.Gateway != nil {
	_, ok := nMap["Gateway"]
	if ok {
		if config.Gateway, err = types.ParseCIDR(nMap["Gateway"].(string)); err != nil {
			return fmt.Errorf("failed to decode DHCP pool IPv4 gateway address after json unmarshal: %s", nMap["Gateway"].(string))
		}
	}
	//}
	if config.IPv4Subnet, err = types.ParseCIDR(nMap["IPv4Subnet"].(string)); err != nil {
		return fmt.Errorf("failed to decode DHCP pool IPv4 network address after json unmarshal: %s", nMap["IPv4Subnet"].(string))
	}

	return nil
}

func (a *Allocator) addPool(dp *dhcpPool, as string) {
	a.Lock()
	addrSpace := a.addrSpaces[as]
	addrSpace.dhcpPools[dp.ID] = dp
	a.Unlock()
}

func (a *Allocator) deletePool(dp string, as string) {
	a.Lock()
	addrSpace := a.addrSpaces[as]
	delete(addrSpace.dhcpPools, dp)
	a.Unlock()
}

func (a *Allocator) getPool(p string, as string) (*dhcpPool, error) {
	a.Lock()
	defer a.Unlock()
	if p == "" {
		return nil, fmt.Errorf("invalid dhcp pool id: %s", p)
	}
	addrSpace := a.addrSpaces[as]

	if dp, ok := addrSpace.dhcpPools[p]; ok {
		return dp, nil
	}

	return nil, fmt.Errorf("dhcp pool not found: %s", p)
}

func (dp *dhcpPool) lease(dl string) *dhcpLease {
	dp.Lock()
	defer dp.Unlock()

	return dp.dhcpLeases[dl]
}

func (dp *dhcpPool) addLease(dl *dhcpLease) {
	dp.Lock()
	dp.dhcpLeases[dl.leaseIP.String()] = dl
	dp.Unlock()
}

func (dp *dhcpPool) deleteLease(dl string) {
	dp.Lock()
	delete(dp.dhcpLeases, dl)
	dp.Unlock()
}

func (dp *dhcpPool) getLease(l string) (*dhcpLease, error) {
	dp.Lock()
	defer dp.Unlock()
	if l == "" {
		return nil, fmt.Errorf("dhcp lease for IP %s not found", l)
	}
	if dl, ok := dp.dhcpLeases[l]; ok {
		return dl, nil
	}

	return nil, nil
}
func (config *dhcpPool) CopyTo(dst *dhcpPool) error {
	dst.ID = config.ID
	dst.DhcpServer = config.DhcpServer
	dst.IPv4Subnet = config.IPv4Subnet
	dst.Gateway = config.Gateway
	dst.DhcpInterface = config.DhcpInterface
	dst.CreatedSlaveLink = config.CreatedSlaveLink
	dst.dhcpLeases = config.dhcpLeases
	dst.dbIndex = config.dbIndex
	dst.dbExists = config.dbExists
	return nil
}
