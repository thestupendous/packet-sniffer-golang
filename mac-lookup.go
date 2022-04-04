package main

import (
    "fmt"

    "github.com/umahmood/macvendors"
)

func main() {
    vendor := macvendors.New()
    var macAddress string
    macAddress = "28:18:78:6D:64:42"
    mac, err := vendor.Lookup(macAddress)
    if err != nil {
        //...
    }
    fmt.Println("full response\n",mac,"  -------]")
    fmt.Println("address : ",mac.Address)
    fmt.Println("company : ",mac.Company)
    fmt.Println("country : ",mac.Country)
    fmt.Println("type : ",mac.Type)
    fmt.Println(mac.MacPrefix)
    fmt.Println(mac.StartHex)
    fmt.Println(mac.EndHex)
}
