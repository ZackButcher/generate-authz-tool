package main

import (
	"fmt"
	"os"
	"reflect"
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

	debug   bool
	verbose bool
}

type APIClient interface {
	// Returns the service topology from skywalking, which needs to be normalized to services in
	// TSB via the 'aggregated metrics' names in each TSB Service.
	GetTopology(start, end time.Time) (*TopologyResponse, error)
	// Calls TSB's ListServices endpoint
	GetServices() ([]Service, error)
	// Service FQN -> Group FQN
	LookupSecurityGroups(services []Service) map[string]string // TODO: multi-error
	// Takes (Service FQN -> Group FQN) and returns the group policy and services in each group
	GetSecurityGroups(serviceFQNToGroupFQN map[string]string) map[string]PolicyAndServices // TODO: multi-error
}

type Runtime struct {
	start  time.Time
	end    time.Time
	server string

	debug   bool
	verbose bool
	client  APIClient
}

var debug = func(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func main() {

	// flags
	var (
		startFlag string
		endFlag   string
		noverbose bool
	)

	// static & runtime configs
	var (
		cfg     = &Config{}
		runtime = &Runtime{}
	)
	cmd := &cobra.Command{
		Use:   "generate-authz-tool",
		Short: "generate-authz-tool: a simple tool for creating TSB authz policies from TSB traffic data",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Set up the app based on config+flags
			if !cfg.debug {
				debug = func(fmt string, args ...any) {}
			}
			if noverbose {
				cfg.verbose = false
			}

			if cfg.server == "" {
				return fmt.Errorf("Server address (-s or --server) can't be empty, need an address like 'tsb.yourcorp.com' or an IP like '127.0.1.10'.")
			} else {
				// normalize the name; in the client code we prefix every call with `https`, so
				// strip any prefix on input so that both address with protocol and without work
				cfg.server = strings.TrimPrefix(cfg.server, "https://")
				cfg.server = strings.TrimPrefix(cfg.server, "http://")

				debug("got TSB string %q", cfg.server)
			}

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

			runtime = &Runtime{
				start:   cfg.start,
				end:     cfg.end,
				server:  cfg.server,
				debug:   cfg.debug,
				verbose: cfg.verbose,
				client:  NewTSBHttpClient(cfg),
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			debugLogJSON := func(data interface{}) { debugLogJSON(runtime, data) }
			// Do the work: get the topology and services
			top, err := runtime.client.GetTopology(runtime.start, runtime.end)
			if err != nil {
				return fmt.Errorf("failed to get server topology: %w", err)
			}
			debugLogJSON(top)

			services, err := runtime.client.GetServices()
			if err != nil {
				return fmt.Errorf("failed to get service list: %w", err)
			}
			debugLogJSON(services)

			// take the data and build the graph of services; we get back a map of service FQN
			// to the set of clients that call it (a map of client FQN to Service object)
			clients := buildGraph(top, services)

			groupNames := runtime.client.LookupSecurityGroups(services)
			groupToPolicy := runtime.client.GetSecurityGroups(groupNames)

			updates := make(map[string]*SecuritySetting)
			creates := make(map[string]*CreateSecuritySettingsRequest)
			noChange := make(map[string]*SecuritySetting)
			for group, policyAndServices := range groupToPolicy {
				debug("processing %q on behalf of %d services, got callers:", group, len(policyAndServices.services))
				accounts := callersForServiceSet(policyAndServices.services, clients)

				// set up a default policy if one didn't exist
				if policyAndServices.existingPolicy == nil {
					debug("could not find an existing policy for %q; creating one", group)

					description := fmt.Sprintf("Generated %s by 'go run github.com/tetrateio/generate-authz-tool' based on traffic from %s to %s for services: %s",
						time.Now().Format(DATE_FORMAT), cfg.start.Format(DATE_FORMAT), cfg.end.Format(DATE_FORMAT), strings.Join(setToString(policyAndServices.services), ", "))

					createReq := NewSecuritySetting("default", "Default", description, accounts)
					debugLogJSON(createReq)

					creates[group] = createReq
				} else {
					// There's an existing policy, let's compute the new one and compare the two
					policy := newAuthorizationSettings(accounts)

					if reflect.DeepEqual(policy, policyAndServices.existingPolicy) {
						// policies are the same, include this in the "no change" set
						noChange[policyAndServices.existingPolicy.FQN] = policyAndServices.existingPolicy
						debug("no change in policy for %q", policyAndServices.existingPolicy.FQN)
						debugLogJSON(policyAndServices.existingPolicy)
					} else {
						if cfg.debug {
							debug("previous policy for %q:", policyAndServices.existingPolicy.FQN)
							debugLogJSON(policyAndServices.existingPolicy)
							debug("updated policy for %q:", policyAndServices.existingPolicy.FQN)
							debugLogJSON(policy)
						}
						// new policy is different than the old policy, update it
						policyAndServices.existingPolicy.Authorization = policy
						updates[group] = policyAndServices.existingPolicy
					}
				}

			}

			printOutput(runtime, clients, groupToPolicy, creates, updates, noChange)
			return err
		},
	}

	cmd.Flags().StringVarP(&cfg.server, "server", "s", "", "Address of the TSB API server, e.g. some.tsb.address.example.com. REQUIRED")
	cmd.Flags().StringVarP(&cfg.username, "http-auth-user", "u", "", "Username to call TSB with via HTTP Basic Auth. REQUIRED")
	cmd.Flags().StringVarP(&cfg.password, "http-auth-password", "p", "", "Password to call TSB with via HTTP Basic Auth. REQUIRED")
	cmd.Flags().StringVar(&cfg.org, "org", "tetrate", "TSB org to query against")
	cmd.Flags().StringVar(&startFlag, "start", fmt.Sprintf(time.Now().Add(-5*24*time.Hour).Format(DATE_FORMAT)),
		"Start of the time range to query the topology in YYYY-MM-DD format")
	cmd.Flags().StringVar(&endFlag, "end", fmt.Sprintf(time.Now().Format(DATE_FORMAT)),
		"End of the time range to query the topology in YYYY-MM-DD format")
	cmd.Flags().BoolVarP(&cfg.insecure, "insecure", "k", false, "Skip certificate verification when calling TSB")
	cmd.Flags().BoolVar(&cfg.debug, "debug", false, "Enable debug logging")
	cmd.Flags().BoolVar(&cfg.verbose, "verbose", true, "Enable verbose output, explaining why policy was generated; otherwise only the policy documents are printed.")
	cmd.Flags().BoolVar(&noverbose, "noverbose", false, "Disable verbose output; overrides --verbose (equivalent to --verbose=false)")

	if err := cmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func printOutput(runtime *Runtime, clients map[string]map[string]*Service, groupToPolicy map[string]PolicyAndServices, creates map[string]*CreateSecuritySettingsRequest, updates map[string]*SecuritySetting, noChange map[string]*SecuritySetting) {
	if runtime.verbose {
		fmt.Printf("Observed the following traffic in the system from %s to %s:\n",
			runtime.start.Format(DATE_FORMAT), runtime.end.Format(DATE_FORMAT))

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
			url := settingsFQNFromGroupName(runtime.server, group)
			fmt.Printf("POST %q\n", url)
			fmt.Println(marshalToString(create))
		}
	}

	if len(updates) > 0 {
		fmt.Println("\nThe following policies need to be updated:\n")
		for _, update := range updates {
			fmt.Printf("PUT https://%s/v2/%s\n", runtime.server, update.FQN)
			fmt.Println(marshalToString(update))
		}
	}

	if len(noChange) > 0 {
		fmt.Println("\nThe following settings already match the observed traffic in the system:\n")
		for group, setting := range noChange {
			fmt.Println("- " + group + ":")
			if runtime.verbose {
				fmt.Println(marshalToString(setting))
			}
		}
	}
}

// Normalizes the topology response and service list into a Graph of Service FQN to the set of callers (with their Service definition)
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

// We do updates per Group, so we want to get all of the callers for the entire group of services to update
// the group policy all at once.
func callersForServiceSet(services map[string]struct{}, graph map[string]map[string]*Service) []string {
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
