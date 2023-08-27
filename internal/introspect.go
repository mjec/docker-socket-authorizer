package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/exp/slog"
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
			slog.Error("Unable to convert empty input to JSON", slog.Any("error", err))
			// Using log.Fatal() here isn't ideal; but I think we're going to get rid of this whole file anyway.
			log.Fatal("Unable to convert empty input to JSON")
		}
		fmt.Printf("%s\n", j)
		os.Exit(0)
	}
	log.Fatalf("Unrecognized dump argument: %s\nMust be one of \"query\", \"meta-policy\" or \"input\".\n", arg)
}
