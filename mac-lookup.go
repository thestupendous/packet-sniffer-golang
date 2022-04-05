package main

import (
    "fmt"
    "os"
    "github.com/umahmood/macvendors"
)

func main() {
    vendor := macvendors.New()
    var macAddress string
    macAddress = os.Args[1]
    fmt.Println("from command line args, mac address : ",macAddress)
    mac, err := vendor.Lookup(macAddress)
    if err != nil {
        //...
    }
    fmt.Println("company : ",mac.Company)
    fmt.Println("address : ",mac.Address)
    fmt.Println("country : ",mac.Country)
    fmt.Println("type : ",mac.Type)
}
