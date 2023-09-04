package internal

import (
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
	remoteAddrName, originalIpNames, err := remoteNames(r)
	if err != nil {
		return Input{}, err
	}

	return Input{
		OriginalIpNames: originalIpNames,
		OriginalUri:     r.Header.Get("X-Original-URI"),
		OriginalMethod:  r.Header.Get("X-Original-Method"),
		OriginalIp:      r.Header.Get("X-Original-IP"),
		Uri:             r.RequestURI,
		RemoteAddr:      r.RemoteAddr,
		RemoteAddrNames: remoteAddrName,
	}, nil
}

func remoteNames(r *http.Request) ([]string, []string, error) {
	remoteAddrName, err := rdns(strings.Split(r.RemoteAddr, ":")[0])
	if err != nil {
		return nil, nil, err
	}
	originalIpNames, err := rdns(r.Header.Get("x-original-ip"))
	if err != nil {
		return nil, nil, err
	}
	return remoteAddrName, originalIpNames, nil
}

func rdns(ip string) ([]string, error) {
	if ip == "" {
		return make([]string, 0), nil
	}

	validNames := make([]string, 0)

	reverseNames, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	for _, name := range reverseNames {
		forwardIps, err := net.LookupHost(name)
		if err != nil {
			return nil, err
		}
		for _, resolvedIp := range forwardIps {
			if resolvedIp == ip {
				validNames = append(validNames, name)
				break
			}
		}

	}
	return validNames, nil
}
