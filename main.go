package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const DATE_FORMAT = "2006-01-02"

type Config struct {
	username string
	password string
	server   string
	org      string
	start    time.Time
	end      time.Time
	insecure bool
}

func defaultConfig() Config {
	return Config{
		username: "admin",
		password: "Tetrate123",
		org:      "tetrate",
	}
}

type Response struct {
	Data struct {
		Topo struct {
			Nodes []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				IsReal bool   `json:"isReal"`
			} `json:"nodes"`
			Calls []struct {
				ID               string   `json:"id"`
				Source           string   `json:"source"`
				SourceComponents []string `json:"sourceComponents"`
				Target           string   `json:"target"`
				TargetComponents []string `json:"targetComponents"`
				DetectPoints     []string `json:"detectPoints"`
			} `json:"calls"`
		} `json:"topo"`
	} `json:"data"`
}

func main() {
	cfg := defaultConfig()

	var (
		startFlag string
		endFlag   string
	)

	cmd := &cobra.Command{
		Use:   "generate-authz",
		Short: "generate-authz - a simple tool for creating TSB authz policies from TSB traffic data",
		RunE: func(cmd *cobra.Command, args []string) error {
			if start, err := time.Parse(DATE_FORMAT, startFlag); err != nil {
				return fmt.Errorf("failed to parse start time %q: %w", startFlag, err)
			} else {
				cfg.start = start
			}
			if end, err := time.Parse(DATE_FORMAT, endFlag); err != nil {
				return fmt.Errorf("failed to parse start time %q: %w", endFlag, err)
			} else {
				cfg.end = end
			}

			client := http.DefaultClient
			if cfg.insecure {
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				client = &http.Client{Transport: tr}
			}

			top, err := getTopology(cfg, client)
			if err != nil {
				return fmt.Errorf("failed to get server topology: %w", err)
			}

			data, err := json.MarshalIndent(top, "", "    ")
			_, err = fmt.Print(string(data))
			return err
		},
	}

	cmd.Flags().StringVarP(&cfg.server, "server", "s", "", "address of the TSB API server, e.g. tcc-staging.tetratelabs.io")
	cmd.Flags().StringVar(&cfg.org, "org", "tetrate", "TSB org")
	cmd.Flags().StringVar(&startFlag, "start", fmt.Sprintf(time.Now().Add(-5*24*time.Hour).Format(DATE_FORMAT)),
		"Start of the time range to query the topology")
	cmd.Flags().StringVar(&endFlag, "end", fmt.Sprintf(time.Now().Format(DATE_FORMAT)),
		"End of the time range to query the topology")
	cmd.Flags().BoolVarP(&cfg.insecure, "insecure", "k", false, "Skip certificate verification when calling TSB")

	if err := cmd.Execute(); err != nil {
		fmt.Println("%v", err)
		os.Exit(-1)
	}
}

func getTopology(cfg Config, client *http.Client) (*Response, error) {
	start := cfg.start.Format(DATE_FORMAT)
	end := cfg.end.Format(DATE_FORMAT)
	query := fmt.Sprintf(`{
    "query":"query ListNodesAndEdges($duration: Duration!) {topo: getGlobalTopology(duration: $duration) { nodes {id ,name, type, isReal } calls { id, source, sourceComponents, target, targetComponents, detectPoints } } }",
    "variables":{"duration":{"start":"%s","end":"%s","step":"DAY"}}
}`, start, end)

	fmt.Printf("issuing query:\n%s\n", query)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/graphql", cfg.server), strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.SetBasicAuth(cfg.username, cfg.password)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue request: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	sample := string(body)
	if len(body) > 80 {
		sample = fmt.Sprintf("%s...", body[0:80])
	}
	fmt.Printf("got body: %s\n", sample)

	out := &Response{}
	err = json.Unmarshal(body, out)
	return out, err
}

type Service struct {
	FQN         string   `json:"fqn"`
	DisplayName string   `json:"displayName"`
	Etag        string   `json:"etag"`
	Description string   `json:"description"`
	ShortName   string   `json:"shortName"`
	Hostnames   []string `json:"hostnames"`
	Ports       []struct {
		Number             int      `json:"number"`
		Name               string   `json:"name"`
		ServiceDeployments []string `json:"serviceDeployments"`
	} `json:"ports"`
	Subsets            []string `json:"subsets"`
	ServiceType        string   `json:"serviceType"`
	ExternalAddresses  []string `json:"externalAddresses"`
	State              string   `json:"state"`
	Metrics            []Metric `json:"metrics"`
	ServiceDeployments []struct {
		FQN    string `json:"fqn"`
		Source string `json:"source"`
	} `json:"serviceDeployments"`
	SubsetDeployments []struct {
		Name               string   `json:"name"`
		ServiceDeployments []string `json:"serviceDeployments"`
	} `json:"subsetDeployments"`
	CanonicalName string   `json:"canonicalName"`
	SpiffeIds     []string `json:"spiffeIds"`
}

type Metric struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	AggregationKey    string `json:"aggregationKey"`
	Type              string `json:"type"`
	ServiceDeployment string `json:"serviceDeployment"`
	ParentMetric      string `json:"parentMetric"`
}
