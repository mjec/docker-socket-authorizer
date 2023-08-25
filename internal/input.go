package internal

import (
	"log"
	"net"
	"net/http"
	"strings"
)

type Input struct {
	OriginalIpNames []string `json:"original_ip_names"`
	OriginalUri     string   `json:"original_uri"`
	OriginalMethod  string   `json:"original_method"`
	OriginalIp      string   `json:"original_ip"`
	Uri             string   `json:"uri"`
	RemoteAddr      string   `json:"remote_addr"`
	RemoteAddrNames []string `json:"remote_addr_names"`
}

func MakeInput(r *http.Request) (Input, error) {
	remote_addr_name, original_ip_names, err := remote_names(r)
	if err != nil {
		return Input{}, err
	}

	return Input{
		OriginalIpNames: original_ip_names,
		OriginalUri:     r.Header.Get("X-Original-URI"),
		OriginalMethod:  r.Header.Get("X-Original-Method"),
		OriginalIp:      r.Header.Get("X-Original-IP"),
		Uri:             r.RequestURI,
		RemoteAddr:      r.RemoteAddr,
		RemoteAddrNames: remote_addr_name,
	}, nil
}

func remote_names(r *http.Request) ([]string, []string, error) {
	remote_addr_name, err := rdns(strings.Split(r.RemoteAddr, ":")[0])
	if err != nil {
		return nil, nil, err
	}
	original_ip_name, err := rdns(r.Header.Get("x-original-ip"))
	if err != nil {
		return nil, nil, err
	}
	return remote_addr_name, original_ip_name, nil
}

func rdns(ip string) ([]string, error) {
	if ip == "" {
		return make([]string, 0), nil
	}

	valid_names := make([]string, 0)

	reverse_names, err := net.LookupAddr(ip)
	if err != nil {
		log.Printf("rDNS error (%s): %s\n", ip, err)
		return nil, err
	}
	for _, name := range reverse_names {
		forward_ips, err := net.LookupHost(name)
		if err != nil {
			log.Printf("Forward DNS error (%s): %s\n", ip, err)
			return nil, err
		}
		for _, resolved_ip := range forward_ips {
			if resolved_ip == ip {
				valid_names = append(valid_names, name)
				break
			}
		}

	}
	return valid_names, nil
}
