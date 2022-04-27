package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/Ullaakut/nmap/v2"
	osfamily "github.com/Ullaakut/nmap/v2/pkg/osfamilies"
)

type Host struct {
	Ip        string  `json:"ip" bson:"ip" bson:"ip"`
	Mac       string  `json:"mac" bson:"mac" bson:"mac"`
	MacVendor string  `json:"mac-vendor" bson:"mac_vendor"`
	Matches   []Match `json:"matches" bson:"matches"`
}

type Match struct {
	Name    string  `json:"match-name" bson:"match_name"`
	Classes []Class `json:"match-class" bson:"match_class"`
}

type Class struct {
	//{Vendor:Microsoft OSGeneration:2016 Type:general purpose Accuracy:96 Family:Windows
	//CPEs:[cpe:/o:microsoft:windows_server_2016]}
	Os         string `json:"class-os" bson:"class_os"` //cat of Vendor+family+generation
	DeviceType string `json:"device-type" bson:"device_type"`
	Accuracy   int    `json:"accuracy" bson:"accuracy"`
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
	fmt.Printf("Enter scan target(s): ")
	var targetString string
	fmt.Scanf("%s", &targetString)
	if len(targetString) < 4 {
		targetString = "192.168.0.0/24"
	}

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targetString),
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

	for _, host := range hosts {
		fmt.Println(host.Ip, host.MacVendor, " :")
		for _, match := range host.Matches {
			fmt.Println("Match:  ", match.Name)
		}
	}

	//dumping to mongodb
	fmt.Println("\tNow Storing to db")
	//connecting to mongo
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		fmt.Println("\t!!MONGO CONNECTION ERROR", err)
	}
	collection := client.Database("hosts_discovery").Collection("nmap_results")
	for i, _ := range hosts {
		result, err := collection.InsertOne(context.TODO(), hosts[i])
		if err != nil {
			panic(err)
		}
		fmt.Println("inserted one : ", result.InsertedID)
	}
	//
	//	out, err := json.Marshal(hosts)
	//	if err != nil {
	//		fmt.Println("\t!!MARSHAL ERROR", err)
	//	}

	//	var hostsMap map[string]interface{}

	//	json.Unmarshal(out, &hostsMap)
	//	res, err := collection.InserMany(context.Background(), hostsMap)
	//	if err != nil {
	//		fmt.Println("\t!!INSERT ERROR", err)
	//	}
	//	_ = res
	//	fmt.Println(res)

}

func countByOS(result *nmap.Run) {
	matchCounter, classCounter := 0, 0
	var (
		linux, windows int
	)

	// Count the number of each OS for all hosts.
	// osType := ""
	i := 0
	var k int
	for _, host := range result.Hosts {
		hostStruct := Host{}
		hostStruct.Init()

		k = 0 //only iterating two times over []addresses
		//once for ip and mac each
		for _, address := range host.Addresses {
			if k > 2 {
				break
			}
			k++
			//0			fmt.Println("host IP: ", address.Addr, address.AddrType, "mac manufacturer:", address.Vendor, host.Hostnames)
			if k == 1 { //IP address
				hostStruct.Ip = address.Addr
			} else if k == 2 { //MAC address
				hostStruct.Mac = address.Addr
				hostStruct.MacVendor = address.Vendor
			}

		}

		//adding matches to host record - working on []Match of host
		i = 1
		for _, match := range host.OS.Matches {
			matchCounter++
			matchStruct := Match{}
			matchStruct.Init()
			//0			fmt.Printf("Match no %d - name: [%d] - Accuracy: [%d]\n", i, match.Name)
			matchStruct.Name = match.Name

			//adding classes to matches - working on []Class of Match
			j := 1
			for _, class := range match.Classes {
				classCounter++
				classStruct := Class{}
				//0				fmt.Printf("  class %d : Type=%v %+v\n", j, class.Type, class)
				classStruct.Os = class.Vendor + class.Family + class.OSGeneration
				classStruct.DeviceType = class.Type
				classStruct.Accuracy = class.Accuracy

				switch class.OSFamily() {
				case osfamily.Linux:
					linux++
				case osfamily.Windows:
					windows++
					//0					fmt.Println("os type : ", class.OSFamily)

				}

				matchStruct.Classes = append(matchStruct.Classes, classStruct)
				j++
			}

			hostStruct.Matches = append(hostStruct.Matches, matchStruct)
			i++
		}
		fmt.Println()
		hosts = append(hosts, hostStruct)
	}
	//printing whole hosts struct list
	//prettyHosts, _ := json.MarshalIndent(hosts, "", "   ")
	//fmt.Println(string(prettyHosts))

	fmt.Printf("Discovered %d linux hosts and %d windows hosts out of %d total up hosts.\n", linux, windows, result.Stats.Hosts.Up)
	fmt.Printf("total no of hosts %d, matches %d, classes %d", len(hosts), matchCounter, classCounter)
}
