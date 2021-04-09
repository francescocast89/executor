package parser

import (
	"encoding/xml"
)

type HostDiscoveryStruct struct {
	XMLName xml.Name `xml:"nmaprun"`
	Host    []Host   `xml:"host"`
}

type Host struct {
	Status Status    `xml:"status"`
	Addr   []Address `xml:"address"`
}
type Status struct {
	State string `xml:"state,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

//Parse function
func Parse(report []byte) (*HostDiscoveryStruct, error) {
	r := HostDiscoveryStruct{}
	err := xml.Unmarshal(report, &r)
	return &r, err
}
