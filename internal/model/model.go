package model

type Suppression struct {
	VulnerabilityName string                `json:"vulnerability,omitempty"`
	Reason            string                `json:"reason,omitempty"`
	State             AnalysisState         `json:"state"`
	Justification     AnalysisJustification `json:"justification"`
	Response          AnalysisResponse      `json:"response"`
	Details           string                `json:"details,omitempty"`
}

type AnalysisState string

const (
	AnalysisStateExploitable   AnalysisState = "EXPLOITABLE"
	AnalysisStateInTriage      AnalysisState = "IN_TRIAGE"
	AnalysisStateFalsePositive AnalysisState = "FALSE_POSITIVE"
	AnalysisStateNotAffected   AnalysisState = "NOT_AFFECTED"
	AnalysisStateResolved      AnalysisState = "RESOLVED"
	AnalysisStateNotSet        AnalysisState = "NOT_SET"
)

type AnalysisJustification string

const (
	AnalysisJustificationCodeNotPresent        AnalysisJustification = "CODE_NOT_PRESENT"
	AnalysisJustificationCodeNotReachable      AnalysisJustification = "CODE_NOT_REACHABLE"
	AnalysisJustificationRequiresConfiguration AnalysisJustification = "REQUIRES_CONFIGURATION"
	AnalysisJustificationRequiresDependency    AnalysisJustification = "REQUIRES_DEPENDENCY"
	AnalysisJustificationRequiresEnvironment   AnalysisJustification = "REQUIRES_ENVIRONMENT"
	AnalysisJustificationProtectedByCompiler   AnalysisJustification = "PROTECTED_BY_COMPILER"
	AnalysisJustificationProtectedAtRuntime    AnalysisJustification = "PROTECTED_AT_RUNTIME"
	AnalysisJustificationProtectedAtPerimeter  AnalysisJustification = "PROTECTED_AT_PERIMETER"
	AnalysisJustificationMitigatingControl     AnalysisJustification = "PROTECTED_BY_MITIGATING_CONTROL"
	AnalysisJustificationNotSet                AnalysisJustification = "NOT_SET"
)

type AnalysisResponse string

const (
	AnalysisResponseCannotFix           AnalysisResponse = "CAN_NOT_FIX"
	AnalysisResponseWillNotFix          AnalysisResponse = "WILL_NOT_FIX"
	AnalysisResponseUpdate              AnalysisResponse = "UPDATE"
	AnalysisResponseRollback            AnalysisResponse = "ROLLBACK"
	AnalysisResponseWorkaroundAvailable AnalysisResponse = "WORKAROUND_AVAILABLE"
	AnalysisResponseNotSet              AnalysisResponse = "NOT_SET"
)
