package main

import (
	"encoding/json"
	"fmt"
)

func marshalToString(data interface{}) string {
	js, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Sprintf("failed to marshal policy into json: %w", err)
	}
	return string(js)
}

func debugLogJSON(r *Runtime, data interface{}) {
	if !r.verbose {
		return
	}

	debug(marshalToString(data))
}

func setToString(set map[string]struct{}) (out []string) {
	for s := range set {
		out = append(out, s)
	}
	return
}
