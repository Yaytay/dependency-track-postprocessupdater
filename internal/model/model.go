package model

type Suppression struct {
	Vulnerability string `json:"vulnerability,omitempty"`
	Reason        string `json:"reason,omitempty"`
}
