package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type TSBHttpClient struct {
	server   string
	org      string
	username string
	password string
	client   *http.Client
}

// compile-time assert we satisfy the interface we intend to
var _ APIClient = &TSBHttpClient{}

func NewTSBHttpClient(cfg *Config) *TSBHttpClient {
	client := http.DefaultClient
	if cfg.insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}
	return &TSBHttpClient{
		server:   cfg.server,
		org:      cfg.org,
		username: cfg.username,
		password: cfg.password,
		client:   client}
}

// Returns the service topology from skywalking, which needs to be normalized to services in
// TSB via the 'aggregated metrics' names in each TSB Service.
func (c *TSBHttpClient) GetTopology(start, end time.Time) (*TopologyResponse, error) {
	s := start.Format(DATE_FORMAT)
	e := end.Format(DATE_FORMAT)
	query := fmt.Sprintf(`{
    "query":"query ListNodesAndEdges($duration: Duration!) {topo: getGlobalTopology(duration: $duration) { nodes {id ,name, type, isReal } calls { id, source, sourceComponents, target, targetComponents, detectPoints } } }",
    "variables":{"duration":{"start":"%s","end":"%s","step":"DAY"}}
}`, s, e)

	debug("issuing query:\n%s", query)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/graphql", c.server), strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	body, err := c.callTSB(req)
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

// Calls TSB's ListServices endpoint
func (c *TSBHttpClient) GetServices() ([]Service, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/v2/organizations/%s/services", c.server, c.org), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	body, err := c.callTSB(req)
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

// Service FQN -> Group FQN
func (c *TSBHttpClient) LookupSecurityGroups(services []Service) map[string]string { // TODO: multi-error
	type SecurityGroupResponse struct {
		SecurityGroups []struct {
			ConfigMode string `json:"configMode"`
			FQN        string `json:"fqn"`
		} `json:"securityGroups"`
	}

	// use the Lookup API to get the groups for each service
	groupNames := map[string]string{}
	for _, svc := range services {
		url := fmt.Sprintf("https://%s/v2/%s/groups", c.server, svc.FQN)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			debug("failed to create request for service groups for %q", svc.FQN)
			continue
		}

		body, err := c.callTSB(req)
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

// Takes (Service FQN -> Group FQN) and returns the group policy and services in each group
func (c *TSBHttpClient) GetSecurityGroups(groupNames map[string]string) map[string]PolicyAndServices {
	const EMPTY_SETTINGS = `{"settings":[]}`
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
		req, err := http.NewRequest(http.MethodGet, settingsFQNFromGroupName(c.server, group), nil)
		if err != nil {
			debug("failed to create request for service groups for %q", group)
			continue
		}

		body, err := c.callTSB(req)
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

func (c *TSBHttpClient) callTSB(req *http.Request) ([]byte, error) {
	debug("sending %v to %q", req.Method, req.URL.String())
	req.Header.Set("content-type", "application/json")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
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
