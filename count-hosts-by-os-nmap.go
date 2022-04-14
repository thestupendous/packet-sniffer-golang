package main

import (
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v2"
	osfamily "github.com/Ullaakut/nmap/v2/pkg/osfamilies"
)

func main() {
	// Equivalent to
	// nmap -F -O 192.168.0.0/24
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("192.168.0.0/24"),
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
	for _, host := range result.Hosts {
		for _,address := range host.Addresses {
			fmt.Println("host IP: ",address.Addr,address.AddrType,"mac manufacturer:",address.Vendor,host.Hostnames)
		}
		fmt.Println("** host full : ",host)
		for _, match := range host.OS.Matches {
			for _, class := range match.Classes {
				// fmt.Println("host os : ",host.OS)			//print all data regarding os fingerprint
				// fmt.Println("host :",host.OS.Matches)
				fmt.Println("host finterprints :",host.OS.Fingerprints)	//print os fingerprints
				fmt.Printf("class : Type=%v %+v\n",class.Type,class,)
				switch class.OSFamily() {
				case osfamily.Linux:
					linux++
					// osType = "linux"
				case osfamily.Windows:
					windows++
					// osType = "Windows"
				fmt.Println("os type : ",class.OSFamily)
				}
			}
		}
		fmt.Println()
	}

	fmt.Printf("Discovered %d linux hosts and %d windows hosts out of %d total up hosts.\n", linux, windows, result.Stats.Hosts.Up)
}
