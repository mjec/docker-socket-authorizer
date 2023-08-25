package main

import (
	"log"
	"net/http"
	"os"

	"github.com/mjec/docker-socket-authorizer/internal"
	"github.com/mjec/docker-socket-authorizer/internal/handlers"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TODO: structured logging

func main() {
	if len(os.Args) == 3 && os.Args[1] == "introspect" {
		internal.Introspect(os.Args[2])
	}

	if err := internal.LoadPolicies(); err != nil {
		log.Fatalf("Error loading policies: %s\n", err)
	}
	// TODO: @CONFIG determine whether to watch files
	go internal.WatchPolicies()

	http.HandleFunc("/reflect", handlers.Reflect)
	http.HandleFunc("/reload", handlers.Reload)
	http.HandleFunc("/authorize", handlers.Authorize)
	http.Handle("/metrics", promhttp.Handler())

	log.Println("Starting server")
	log.Fatal(http.ListenAndServe(":8080", nil)) // TODO: @CONFIG port
}
