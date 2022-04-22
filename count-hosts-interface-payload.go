package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v2"
	osfamily "github.com/Ullaakut/nmap/v2/pkg/osfamilies"
)

func main() {
	// Equivalent to
	// nmap -F -O 192.168.0.0/24
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("172.22.22.0/24"),
		nmap.WithFastMode(),
		nmap.WithOSDetection(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("nmap scan failed: %v", err)
	}

	countByOS(result)
}

func countByOS(result *nmap.Run) {
	var (
		linux, windows int
	)

	// Count the number of each OS for all hosts.
	// osType := ""
	i := 0
	for _, host := range result.Hosts {
		for _, address := range host.Addresses {
			fmt.Println("host IP: ", address.Addr, address.AddrType, "mac manufacturer:", address.Vendor, host.Hostnames)
		}
		//fmt.Println("** host full : ",host)
		i = 1
		for _, match := range host.OS.Matches {
			fmt.Printf("Match no %d\n", i)
			j := 1
			for _, class := range match.Classes {
				// fmt.Println("host os : ",host.OS)			//print all data regarding os fingerprint
				// fmt.Println("host :",host.OS.Matches)
				//fmt.Println("host finterprints :",host.OS.Fingerprints)	//print os fingerprints
				fmt.Printf("class %d : Type=%v %+v\n", j, class.Type, class)
				data, err := json.Marshal(class)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println("*****JSON**********")
				fmt.Println(string(data))
				var out map[string]interface{}
				json.Unmarshal(data, &out)
				fmt.Println("#####MAP###############")
				fmt.Println(out)
				fmt.Println("Acurracy", out["accuracy"])
				switch class.OSFamily() {
				case osfamily.Linux:
					linux++
					// osType = "linux"
				case osfamily.Windows:
					windows++
					// osType = "Windows"
					fmt.Println("os type : ", class.OSFamily)
				}
				j++
			}
			i++
		}
		fmt.Println()
	}

	fmt.Printf("Discovered %d linux hosts and %d windows hosts out of %d total up hosts.\n", linux, windows, result.Stats.Hosts.Up)
}
