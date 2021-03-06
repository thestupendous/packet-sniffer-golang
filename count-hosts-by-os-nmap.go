package main

import (
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v2"
	osfamily "github.com/Ullaakut/nmap/v2/pkg/osfamilies"
)

type Host struct {
	Ip        string
	Mac       string
	MacVendor string
	Matches   []Match
}

type Match struct {
	Accuracy int
	Classes  []Class
}

type Class struct {
	//{"vendor":"Cisco","os_generation":"15.X","type":"WAP","accuracy":100,"os_family":"IOS",
	//"cpes":["cpe:/h:cisco:aironet_1141n","cpe:/h:cisco:aironet_3602i","cpe:/o:cisco:ios:12.4","cpe:/o:cisco:ios:15.3"]}
	Os         string //cat of Vendor+family+generation
	DeviceType string
	Accuracy   int
}

func (h *Host) Init() {
	h.Matches = make([]Match, 0)
}

func (m *Match) Init() {
	m.Classes = make([]Class, 0)
}

//global data store - hosts slice
var hosts []Host

func main() {
	//	hosts := make([]Host, 0)
	// Equivalent to
	// nmap -F -O 192.168.0.0/24

	hosts = make([]Host, 0)

	scanner, err := nmap.NewScanner(
		nmap.WithTargets("192.168.31.0/24"),
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
	var k int
	for _, host := range result.Hosts {
		k = 0 //only iterating two times over []addresses
		//once for ip and mac each
		for _, address := range host.Addresses {
			if k > 2 {
				break
			}
			k++
			fmt.Println("host IP: ", address.Addr, address.AddrType, "mac manufacturer:", address.Vendor, host.Hostnames)

		}
		//fmt.Println("** host full : ",host)
		i = 1
		for _, match := range host.OS.Matches {
			fmt.Printf("Match no %d - name: [%d] - Accuracy: [%d]\n", i, match.Name)
			j := 1
			for _, class := range match.Classes {
				// fmt.Println("host os : ",host.OS)			//print all data regarding os fingerprint
				// fmt.Println("host :",host.OS.Matches)
				//fmt.Println("host finterprints :",host.OS.Fingerprints)	//print os fingerprints
				fmt.Printf("  class %d : Type=%v %+v\n", j, class.Type, class)
				//				data, err := json.Marshal(class)
				//				if err != nil {
				//					fmt.Println(err)
				//				}
				//				fmt.Println("*****JSON**********")
				//				fmt.Println(string(data))
				//				var out map[string]interface{}
				//				json.Unmarshal(data, &out)
				//				fmt.Println("#####MAP###############")
				//				fmt.Println(out)
				//				fmt.Println("Acurracy", out["accuracy"])
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
