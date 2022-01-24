package main

import (
	"fmt"
	"strings"
)

type IPAddress struct {
	Address string
	ThreatCrowdResponse *ThreatCrowdResponse
	GreyNoiseMultiResponse * GreyNoiseMultiResponse
}

func (ip *IPAddress) SetIP(val string) {
	ip.Address = val
}

func (ip *IPAddress) SetThreatCrowdResponse(val *ThreatCrowdResponse) {
	ip.ThreatCrowdResponse = val
}

func (ip *IPAddress) SetGreyNoiseMultiResponse(val *GreyNoiseMultiResponse) {
	ip.GreyNoiseMultiResponse = val
}

func (ip *IPAddress) Find() error {
	if len(ip.Address) == 0 {
		return fmt.Errorf("ip address length is 0... need to set an ip")
	}
	tc, gn := Find(ip.Address)
	ip.ThreatCrowdResponse = tc
	ip.GreyNoiseMultiResponse = gn
	return nil
}

func (ip *IPAddress) IsSus() bool {
	if len(ip.Address) == 0 {
		fmt.Println("ip address length is 0... need to set an ip")
		return false
	}
	isSus := false
	if ip.GreyNoiseMultiResponse == nil {
		fmt.Println("no greynoise entry found")
	} else {
		isSus = (!ip.GreyNoiseMultiResponse.Riot && ip.GreyNoiseMultiResponse.Noise) || strings.Contains(ip.GreyNoiseMultiResponse.Classification, "malicious")
		fmt.Println("found entry in greynoise...")
	}
	if ip.ThreatCrowdResponse == nil {
		fmt.Println("no threatcrowd entry found")
	} else {
		fmt.Println("found entry in threatcrowd")
		if !isSus {
			isSus = ip.ThreatCrowdResponse.Votes < 0
		}
	}
	return isSus
}

func (ip *IPAddress) PrintInfo() string {
	retVal := "GreyNoise\n\tNoise? %t\n\tRIOT? %t\n\tClassification: %s\n\nThreatcrowd\n\tVotes: %d\n"
	return fmt.Sprintf(retVal, ip.GreyNoiseMultiResponse.Noise,
		ip.GreyNoiseMultiResponse.Riot,
		ip.GreyNoiseMultiResponse.Classification,
		ip.ThreatCrowdResponse.Votes)
}