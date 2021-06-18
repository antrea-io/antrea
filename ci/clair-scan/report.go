package main

// These are copied from https://github.com/arminc/clair-scanner, which
// generates the reports we analyze.

type vulnerabilityInfo struct {
	FeatureName    string `json:"featurename"`
	FeatureVersion string `json:"featureversion"`
	Vulnerability  string `json:"vulnerability"`
	Namespace      string `json:"namespace"`
	Description    string `json:"description"`
	Link           string `json:"link"`
	Severity       string `json:"severity"`
	FixedBy        string `json:"fixedby"`
}

type vulnerabilityReport struct {
	Image           string              `json:"image"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []vulnerabilityInfo `json:"vulnerabilities"`
}
