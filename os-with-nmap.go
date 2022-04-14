package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/Ullaakut/nmap/v2"
	"encoding/json"
	"bytes"
)

// func PrettyStruct(data interface{}) (string, error) {
//     val, err := json.MarshalIndent(data, "", "    ")
//     if err != nil {
//         return "", err
//     }
//     return string(val), nil
// }

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
    // with a 5 minute timeout.
    scanner, err := nmap.NewScanner(
        nmap.WithTargets("172.22.22.254"), //"google.com", "facebook.com", "youtube.com"),
        nmap.WithPorts("1-5000"),
		nmap.WithOSDetection(),
        nmap.WithContext(ctx),
    )
    if err != nil {
        log.Fatalf("unable to create nmap scanner: %v", err)
    }

    result, warnings, err := scanner.Run()
    if err != nil {
        log.Fatalf("unable to run nmap scan: %v", err)
    }

    if warnings != nil {
        log.Printf("Warnings: \n %v", warnings)
    }


	//host OS information detection
	resultk, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("nmap scan failed: %v", err)
	} else {
		info := fmt.Sprintf("%s",resultk)
		var prettyJSON bytes.Buffer
		json.Indent(&prettyJSON, []byte(info), "", "    ")
		prettyString := prettyJSON.String()
		fmt.Println("host os results : ",prettyString)
		fmt.Println("raw info: ",resultk)
	}

    for _, host := range result.Hosts {
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            continue
        }

        fmt.Printf("Host %q:\n", host.Addresses[0])

        for _, port := range host.Ports {
            fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
        }
    }

    fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}