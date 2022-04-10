package main

import (
    "fmt"
    "os"
    "github.com/umahmood/macvendors"
)

type MacResult struct {
      MacAddress string
      Company string
      Address string
      Country string
      Type string
}

func MacLookup(macAddress string) *MacResult{
    vendor := macvendors.New()
    mac, err := vendor.Lookup(macAddress)
    if err != nil {
        panic(err)
    }
    res := MacResult{}
    res.MacAddress = macAddress
    res.Company = mac.Company
    res.Address = mac.Address
    res.Country = mac.Country
    res.Type = mac.Type

    return &res
}

func main() {
    var macAddress string
    macAddress = os.Args[1]
    fmt.Println("from command line args, mac address : ",macAddress)

    var p *MacResult = MacLookup(macAddress)
    fmt.Println("company : ",p.Company)
    fmt.Println("address : ",p.Address)
    fmt.Println("country : ",p.Country)
    fmt.Println("type : ",p.Type)
}
