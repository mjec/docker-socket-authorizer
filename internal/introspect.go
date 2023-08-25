package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func Introspect(arg string) {
	if arg == "query" {
		fmt.Printf("%s\n", QUERY)
		os.Exit(0)
	}
	if arg == "meta-policy" {
		fmt.Printf("%s\n", META_POLICY)
		os.Exit(0)
	}
	if arg == "input" {
		j, err := json.Marshal(Input{
			OriginalIpNames: make([]string, 0),
			OriginalUri:     "",
			OriginalMethod:  "",
			OriginalIp:      "",
			Uri:             "",
			RemoteAddr:      "",
			RemoteAddrNames: make([]string, 0),
		})
		if err != nil {
			log.Fatalf("Error marshalling empty input: %s\n", err)
		}
		fmt.Printf("%s\n", j)
		os.Exit(0)
	}
	log.Fatalf("Unrecognized dump argument: %s\nMust be one of \"query\", \"meta-policy\" or \"input\".\n", arg)
}
