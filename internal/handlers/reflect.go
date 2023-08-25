package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/mjec/docker-socket-authorizer/internal"
)

func Reflect(w http.ResponseWriter, r *http.Request) {
	input, err := internal.MakeInput(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Invalid request")
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Forbidden")
		return
	}
	w.Header().Add("content-type", "application/json")
	j, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Unable to marshal input")
		log.Printf("Unable to marshal input: %s\n", err)
		return
	}
	fmt.Fprintf(w, "%s\n", j)
}
