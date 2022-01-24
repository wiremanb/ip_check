package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const (
	ThreatCrowdIPSearch = "https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=%s"
	GreyNoiseMultiQuick = "https://api.greynoise.io/v3/community/%s"
)

type ThreatCrowdResponse struct {
	ResponseCode string `json:"response_code"`
	Resolutions  []struct {
		LastResolved string `json:"last_resolved"`
		Domain       string `json:"domain"`
	} `json:"resolutions"`
	Hashes     []string      `json:"hashes"`
	References []interface{} `json:"references"`
	Votes      int           `json:"votes"`
	Permalink  string        `json:"permalink"`
}

type GreyNoiseMultiResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func Find(ip string) (*ThreatCrowdResponse, *GreyNoiseMultiResponse) {
	resp, err := http.Get(fmt.Sprintf(ThreatCrowdIPSearch, ip))
	if err != nil {
		fmt.Printf("error making tc GET: %v", err)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error reading tc body: %v", err)
	}
	defer resp.Body.Close()

	var tc ThreatCrowdResponse
	err = json.Unmarshal(respBody, &tc)
	if err != nil {
		fmt.Printf("error unmarshalling tc: %v", err)
	}

	resp, err = http.Get(fmt.Sprintf(GreyNoiseMultiQuick, ip))
	if err != nil {
		fmt.Printf("error making gn GET: %v", err)
	}
	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error reading gn body: %v", err)
	}
	defer resp.Body.Close()

	var gn GreyNoiseMultiResponse
	err = json.Unmarshal(respBody, &gn)
	if err != nil {
		fmt.Printf("error unmarshalling gn: %v", err)
	}

	return &tc, &gn
}