package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	lossless "github.com/joeshaw/json-lossless"
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

	debug   bool
	verbose bool
}

func defaultConfig() Config {
	return Config{
		username: "admin",
		password: "Tetrate123",
		org:      "tetrate",
	}
}

var (
	startFlag string
	endFlag   string
	noverbose bool

	debug = func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
	cfg   = defaultConfig()
)

func main() {
	cmd := &cobra.Command{
		Use:   "generate-authz",
		Short: "generate-authz - a simple tool for creating TSB authz policies from TSB traffic data",
		RunE:  RunE,
	}

	cmd.Flags().StringVarP(&cfg.server, "server", "s", "", "address of the TSB API server, e.g. tcc-staging.tetratelabs.io")
	cmd.Flags().StringVar(&cfg.org, "org", "tetrate", "TSB org")
	cmd.Flags().StringVar(&startFlag, "start", fmt.Sprintf(time.Now().Add(-5*24*time.Hour).Format(DATE_FORMAT)),
		"Start of the time range to query the topology")
	cmd.Flags().StringVar(&endFlag, "end", fmt.Sprintf(time.Now().Format(DATE_FORMAT)),
		"End of the time range to query the topology")
	cmd.Flags().BoolVarP(&cfg.insecure, "insecure", "k", false, "Skip certificate verification when calling TSB")
	cmd.Flags().BoolVar(&cfg.debug, "debug", false, "Enable debug logging")
	cmd.Flags().BoolVar(&cfg.verbose, "verbose", true, "Enable verbose output, explaining why policy was generated; otherwise only the policy documents are printed.")
	cmd.Flags().BoolVar(&noverbose, "noverbose", false, "Disable verbose output; overrides --verbose (equivalent to --verbose=false)")

	if err := cmd.Execute(); err != nil {
		fmt.Println("%v", err)
		os.Exit(-1)
	}
}

func RunE(cmd *cobra.Command, args []string) error {
	// Set up the app based on config+flags
	if !cfg.debug {
		debug = func(fmt string, args ...any) {}
	}
	if noverbose {
		cfg.verbose = false
	}

	debugLogJSON := func(data interface{}) { debugLogJSON(cfg, data) }

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

	// Do the work: get the topology and services
	top, err := getTopology(cfg, client)
	if err != nil {
		return fmt.Errorf("failed to get server topology: %w", err)
	}
	debugLogJSON(top)

	services, err := getServices(cfg, client)
	if err != nil {
		return fmt.Errorf("failed to get service list: %w", err)
	}
	debugLogJSON(services)

	// take the data and build the graph of services; we get back a map of service FQN
	// to the set of clients that call it (a map of client FQN to Service object)
	clients := buildGraph(top, services)

	groupToPolicy, err := getSecurityGroupForServices(cfg, client, services)
	if err != nil {
		return fmt.Errorf("failed to look up security groups: %w", err)
	}

	updates := make(map[string]*SecuritySetting)
	creates := make(map[string]*CreateSecuritySettingsRequest)
	noChange := make(map[string]*SecuritySetting)
	for group, policyAndServices := range groupToPolicy {
		debug("processing %q on behalf of %d services, got callers:", group, len(policyAndServices.services))
		accounts := getCallers(policyAndServices.services, clients)

		// set up a default policy if one didn't exist
		if policyAndServices.existingPolicy == nil {
			debug("could not find an existing policy for %q; creating one", group)

			description := fmt.Sprintf("Generated %s by `tctl x gen-authz-policy` based on traffic from %s to %s for services: %s",
				time.Now().Format(DATE_FORMAT), cfg.start.Format(DATE_FORMAT), cfg.end.Format(DATE_FORMAT), strings.Join(setToString(policyAndServices.services), ", "))

			createReq := NewSecuritySetting("default", "Default", description, accounts)
			debugLogJSON(createReq)

			creates[group] = createReq
		} else {
			policy := newAuthorizationSettings(accounts)

			if reflect.DeepEqual(policy, policyAndServices.existingPolicy) {
				noChange[policyAndServices.existingPolicy.FQN] = policyAndServices.existingPolicy
				debug("no change in policy for %q", policyAndServices.existingPolicy.FQN)
			} else {
				policyAndServices.existingPolicy.Authorization = policy
				updates[group] = policyAndServices.existingPolicy

				debugLogJSON(policyAndServices.existingPolicy)
			}
		}

	}

	if cfg.verbose {
		fmt.Printf("Observed the following traffic in the system from %s to %s:\n",
			cfg.start.Format(DATE_FORMAT), cfg.end.Format(DATE_FORMAT))

		for target, callers := range clients {
			fmt.Println("\n  " + target + " is called by:")
			if len(callers) == 0 {
				fmt.Println("    nothing")
			}
			for caller := range callers {
				fmt.Println("  - " + caller)
			}
		}

		fmt.Println("\nThey belong to the following groups:")
		for group, pAndS := range groupToPolicy {
			fmt.Println("\n  " + group + " configures:")
			if len(pAndS.services) == 0 {
				fmt.Println("    nothing")
			}
			for svc := range pAndS.services {
				fmt.Println("  - " + svc)
			}
		}

		fmt.Println()
	}

	if len(creates) > 0 {
		fmt.Println("The following policies need to be created:\n")
		for group, create := range creates {
			url := settingsFQNFromGroupName(cfg, group)
			fmt.Printf("POST %q\n", url)
			fmt.Println(marshalToString(create))
		}
	}

	if len(updates) > 0 {
		fmt.Println("\nThe following policies need to be updated:\n")
		for _, update := range updates {
			fmt.Printf("PUT %q\n", update.FQN)
			fmt.Println(marshalToString(update))
		}
	}

	if len(noChange) > 0 {
		fmt.Println("\nThe following settings already match the observed traffic in the system:\n")
		for group, setting := range noChange {
			fmt.Println("- " + group + ":")
			if cfg.verbose {
				fmt.Println(marshalToString(setting))
			}
		}
	}
	return err
}

func marshalToString(data interface{}) string {
	js, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Sprintf("failed to marshal policy into json: %w", err)
	}
	return string(js)
}

func debugLogJSON(cfg Config, data interface{}) {
	if !cfg.verbose {
		return
	}

	debug(marshalToString(data))
}

func getCallers(services map[string]struct{}, graph map[string]map[string]*Service) []string {
	collectSpiffeIDs := func(unique map[string]struct{}, callers map[string]*Service) map[string]struct{} {
		for name, svc := range callers {
			for _, id := range svc.SpiffeIds {
				spiffeID := id
				if idx := strings.Index(id, "/ns/"); idx > 0 {
					// id[idx+4:] = /ns/<namespace>/sa/<service account> => <namespace>/sa/<service account>
					// Replace('<namespace>/sa/<service account>', '/sa') => <namespace>/<service account>
					spiffeID = strings.Replace(id[idx+4:], "/sa", "", 1)
				}
				debug("- %s (unique[%q] = %q)", name, id, spiffeID)
				unique[spiffeID] = struct{}{}
			}
		}
		return unique
	}

	unique := map[string]struct{}{}
	for svc := range services {
		callers, ok := graph[svc]
		if !ok {
			debug("didn't find clients for %q, skipping", svc)
			continue
		}

		unique = collectSpiffeIDs(unique, callers)
		debug("%d callers for the group after processing %q", len(unique), svc)
	}

	accounts := []string{}
	for id := range unique {
		accounts = append(accounts, id)
	}
	debug("accounts: %v", accounts)
	return accounts
}

func buildGraph(top *TopologyResponse, services []Service) map[string]map[string]*Service {
	servicesByTopKey := make(map[string]*Service)
	for _, svc := range services {
		local := svc
		for _, metric := range svc.Metrics {
			debug("service %q has FQN %q", metric.AggregationKey, local.FQN)
			servicesByTopKey[metric.AggregationKey] = &local
		}
	}

	idToTopKey := make(map[string]string)
	for _, node := range top.Nodes {
		debug("node ID %q belongs to %q", node.ID, node.AggregationKey)
		idToTopKey[node.ID] = node.AggregationKey
	}

	servicesByID := make(map[string]*Service)
	for id, key := range idToTopKey {
		if svc, ok := servicesByTopKey[key]; ok {
			servicesByID[id] = svc
			debug("id %q maps to service %q", id, svc.FQN)
		} else {
			debug("no service for key %q", key)
		}
	}

	clients := make(map[string]map[string]*Service)
	for _, traffic := range top.Calls {
		debug("processing call %s", traffic.ID)

		target, ok := servicesByID[traffic.Target]
		if !ok {
			debug("no service for key %s", traffic.Target)
			continue
		}
		debug("computed target %s", target.FQN)

		// first time we hit a new service, create the set of clients
		if _, ok := clients[target.FQN]; !ok {
			debug("first time seeing service %q, creating map to hold clients", target.FQN)
			clients[target.FQN] = make(map[string]*Service)
		}

		// if the traffic source exists as a service, add it as one of our clients
		if source, ok := servicesByID[traffic.Source]; ok {
			debug("marked %q as client of %q", source.FQN, target.FQN)
			clients[target.FQN][source.FQN] = source
		} else {
			debug("* no service for key %q", traffic.Source)
		}
	}
	return clients
}

type TopologyResponse struct {
	Nodes []struct {
		ID             string `json:"id"`
		AggregationKey string `json:"name"`
	} `json:"nodes"`
	Calls []struct {
		ID     string `json:"id"`
		Source string `json:"source"`
		Target string `json:"target"`
	} `json:"calls"`
}

func getTopology(cfg Config, client *http.Client) (*TopologyResponse, error) {
	start := cfg.start.Format(DATE_FORMAT)
	end := cfg.end.Format(DATE_FORMAT)
	query := fmt.Sprintf(`{
    "query":"query ListNodesAndEdges($duration: Duration!) {topo: getGlobalTopology(duration: $duration) { nodes {id ,name, type, isReal } calls { id, source, sourceComponents, target, targetComponents, detectPoints } } }",
    "variables":{"duration":{"start":"%s","end":"%s","step":"DAY"}}
}`, start, end)

	debug("issuing query:\n%s", query)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/graphql", cfg.server), strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	body, err := callTSB(cfg, client, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get topology: %w", err)
	}

	type respData struct {
		Data struct {
			Response TopologyResponse `json:"topo"`
		} `json:"data"`
	}

	out := &respData{}
	err = json.Unmarshal(body, out)
	return &out.Data.Response, err
}

type Service struct {
	FQN         string `json:"fqn"`
	DisplayName string `json:"displayName"`
	Metrics     []struct {
		AggregationKey string `json:"aggregationKey"`
	} `json:"metrics"`
	CanonicalName string   `json:"canonicalName"`
	SpiffeIds     []string `json:"spiffeIds"`
}

func getServices(cfg Config, client *http.Client) ([]Service, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/v2/organizations/%s/services", cfg.server, cfg.org), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	body, err := callTSB(cfg, client, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}

	type respData struct {
		Services []Service `json:"services"`
	}
	out := &respData{}
	err = json.Unmarshal(body, &out)
	return out.Services, err
}

func getSecurityGroupForServices(cfg Config, client *http.Client, services []Service) (map[string]PolicyAndServices, error) {
	debug("getting sercurity groups for %d services", len(services))
	groupNames := lookupGroups(cfg, client, services)
	out := _getSecurityGroups(cfg, client, groupNames)
	return out, nil
}

type PolicyAndServices struct {
	existingPolicy *SecuritySetting
	services       map[string]struct{}
}

const EMPTY_SETTINGS = `{"settings":[]}`

func _getSecurityGroups(cfg Config, client *http.Client, groupNames map[string]string) map[string]PolicyAndServices {
	// services often share groups, and we make an HTTP request for each group -- so we'll flip this map around
	// into a set of groups with the set of services belonging to each group
	servicesByGroup := make(map[string]map[string]struct{})
	for svc, group := range groupNames {
		if members, ok := servicesByGroup[group]; ok {
			members[svc] = struct{}{}
		} else {
			servicesByGroup[group] = map[string]struct{}{svc: struct{}{}}
		}
	}

	// call GET on each group so we can update the policy

	out := make(map[string]PolicyAndServices)
	for group, svcs := range servicesByGroup {
		debug("processing %q on behalf of %d services", group, len(svcs))
		req, err := http.NewRequest(http.MethodGet, settingsFQNFromGroupName(cfg, group), nil)
		if err != nil {
			debug("failed to create request for service groups for %q", group)
			continue
		}

		body, err := callTSB(cfg, client, req)
		if err != nil {
			debug("failed to get group %q: %v", group, err)
			continue
		}

		if string(body) == EMPTY_SETTINGS {
			out[group] = PolicyAndServices{
				existingPolicy: nil,
				services:       svcs,
			}
		} else {
			resp := &ListSecuritySettingsResponse{}
			if err = json.Unmarshal(body, &resp); err != nil {
				debug("failed to unmarshal %q: %v", group, err)
				continue
			}

			if len(resp.Settings) == 0 {
				debug("we had a setting, but it doesn't exist when we GET it for %q", group)
				continue
			} else if len(resp.Settings) > 1 {
				debug("we had multiple settings for group %q -- which should never happen; proceeding with the first", group)
			}
			out[group] = PolicyAndServices{
				existingPolicy: resp.Settings[0],
				services:       svcs,
			}
		}

	}
	return out
}

func settingsFQNFromGroupName(cfg Config, group string) string {
	return fmt.Sprintf("https://%s/v2/%s/settings", cfg.server, group)
}

type CreateSecuritySettingsRequest struct {
	Name     string           `json:"name"`
	Settings *SecuritySetting `json:"settings"`
}

type SecuritySetting struct {
	lossless.JSON `json:"-"`

	FQN           string                `json:"fqn"`
	DisplayName   string                `json:"displayName"`
	Description   string                `json:"description"`
	Authorization *AuthorizationSetting `json:"authorization"`
}

func (s *SecuritySetting) UnmarshalJSON(data []byte) error {
	return s.JSON.UnmarshalJSON(s, data)
}

func (s *SecuritySetting) MarshalJSON() ([]byte, error) {
	return s.JSON.MarshalJSON(s)
}

type ListSecuritySettingsResponse struct {
	Settings []*SecuritySetting `json:"settings"`
}

type AuthorizationSetting struct {
	Mode            string   `json:"mode"`
	ServiceAccounts []string `json:"serviceAccounts"`
}

func NewSecuritySetting(name string, displayName string, description string, accounts []string) *CreateSecuritySettingsRequest {
	return &CreateSecuritySettingsRequest{
		Name: name,
		Settings: &SecuritySetting{
			DisplayName:   displayName,
			Description:   description,
			Authorization: newAuthorizationSettings(accounts),
		},
	}
}

func newAuthorizationSettings(accounts []string) *AuthorizationSetting {
	return &AuthorizationSetting{
		Mode:            "CUSTOM",
		ServiceAccounts: accounts,
	}
}

// Service FQN -> Group FQN
func lookupGroups(cfg Config, client *http.Client, services []Service) map[string]string {
	type SecurityGroupResponse struct {
		SecurityGroups []struct {
			ConfigMode string `json:"configMode"`
			FQN        string `json:"fqn"`
		} `json:"securityGroups"`
	}

	// use the Lookup API to get the groups for each service
	groupNames := map[string]string{}
	for _, svc := range services {
		url := fmt.Sprintf("https://%s/v2/%s/groups", cfg.server, svc.FQN)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			debug("failed to create request for service groups for %q", svc.FQN)
			continue
		}

		body, err := callTSB(cfg, client, req)
		if err != nil {
			debug("failed to get service groups for %q: %v", svc.FQN, err)
			continue
		}

		resp := &SecurityGroupResponse{}
		if err = json.Unmarshal(body, &resp); err != nil {
			debug("failed to unmarshal %q: %v", svc.FQN, err)
			continue
		}

		for _, group := range resp.SecurityGroups {
			if group.ConfigMode == "BRIDGED" {
				groupNames[svc.FQN] = group.FQN
			}
		}
	}
	return groupNames
}

func callTSB(cfg Config, client *http.Client, req *http.Request) ([]byte, error) {
	debug("sending %v to %q", req.Method, req.URL.String())
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
	debug("got body: %s", sample)
	return body, nil
}

func setToString(set map[string]struct{}) (out []string) {
	for s := range set {
		out = append(out, s)
	}
	return
}
