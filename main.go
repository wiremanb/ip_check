package main

import "fmt"

func main() {
	ip := IPAddress{
		Address:                "60.13.7.210",
		ThreatCrowdResponse:    nil,
		GreyNoiseMultiResponse: nil,
	}

	err := ip.Find()
	if err != nil {
		fmt.Printf("problem finding IP: %v", err)
	}
	fmt.Printf("%s is sus? %t\n%s", ip.Address, ip.IsSus(), ip.PrintInfo())
}