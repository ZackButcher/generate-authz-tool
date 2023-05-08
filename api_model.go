package main

import (
	"fmt"
	lossless "github.com/joeshaw/json-lossless"
)

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

type Service struct {
	FQN         string `json:"fqn"`
	DisplayName string `json:"displayName"`
	Metrics     []struct {
		AggregationKey string `json:"aggregationKey"`
	} `json:"metrics"`
	CanonicalName string   `json:"canonicalName"`
	SpiffeIds     []string `json:"spiffeIds"`
}

type PolicyAndServices struct {
	existingPolicy *SecuritySetting
	services       map[string]struct{}
}

func settingsFQNFromGroupName(server string, group string) string {
	return fmt.Sprintf("https://%s/v2/%s/settings", server, group)
}

type CreateSecuritySettingsRequest struct {
	Name     string           `json:"name"`
	Settings *SecuritySetting `json:"settings"`
}

// We don't want to model the full SecuritySetting object in the TSB API, and we don't want to
// pull in the proto go definitions cause it makes the build a PITA, so we use lossless json to
// preserve all the unknown fields and pull out just the ones we need to work on.
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
