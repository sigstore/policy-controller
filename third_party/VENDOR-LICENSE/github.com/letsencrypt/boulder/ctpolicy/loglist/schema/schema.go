// Code generated by github.com/atombender/go-jsonschema, DO NOT EDIT.

package schema

import "fmt"
import "encoding/json"
import "reflect"

type LogListSchemaJson struct {
	// The time at which this version of the log list was published.
	LogListTimestamp *string `json:"log_list_timestamp,omitempty"`

	// People/organizations that run Certificate Transparency logs.
	Operators []LogListSchemaJsonOperatorsElem `json:"operators"`

	// The version will change whenever a change is made to any part of this log list.
	Version *string `json:"version,omitempty"`
}

type LogListSchemaJsonOperatorsElem struct {
	// The log operator can be contacted using any of these email addresses.
	Email []string `json:"email"`

	// Details of Certificate Transparency logs run by this operator.
	Logs []LogListSchemaJsonOperatorsElemLogsElem `json:"logs"`

	// Name corresponds to the JSON schema field "name".
	Name string `json:"name"`
}

type LogListSchemaJsonOperatorsElemLogsElem struct {
	// A human-readable description that can be used to identify this log.
	Description *string `json:"description,omitempty"`

	// The API endpoints are defined in
	// https://github.com/google/certificate-transparency-rfcs/blob/master/dns/draft-ct-over-dns.md.
	Dns *string `json:"dns,omitempty"`

	// The log's public key as a DER-encoded ASN.1 SubjectPublicKeyInfo structure,
	// then encoded as base64 (https://tools.ietf.org/html/rfc5280#section-4.1.2.7).
	Key string `json:"key"`

	// This is the LogID found in SCTs issued by this log
	// (https://tools.ietf.org/html/rfc6962#section-3.2).
	LogId string `json:"log_id"`

	// The purpose of this log, e.g. test.
	LogType *LogListSchemaJsonOperatorsElemLogsElemLogType `json:"log_type,omitempty"`

	// The CT log should not take longer than this to incorporate a certificate
	// (https://tools.ietf.org/html/rfc6962#section-3).
	Mmd float64 `json:"mmd"`

	// If the log has changed operators, this will contain a list of the previous
	// operators, along with the timestamp when they stopped operating the log.
	PreviousOperators []LogListSchemaJsonOperatorsElemLogsElemPreviousOperatorsElem `json:"previous_operators,omitempty"`

	// State corresponds to the JSON schema field "state".
	State *LogListSchemaJsonOperatorsElemLogsElemState `json:"state,omitempty"`

	// The log will only accept certificates that expire (have a NotAfter date)
	// between these dates.
	TemporalInterval *LogListSchemaJsonOperatorsElemLogsElemTemporalInterval `json:"temporal_interval,omitempty"`

	// The API endpoints are defined in https://tools.ietf.org/html/rfc6962#section-4.
	Url string `json:"url"`
}

type LogListSchemaJsonOperatorsElemLogsElemLogType string

const LogListSchemaJsonOperatorsElemLogsElemLogTypeProd LogListSchemaJsonOperatorsElemLogsElemLogType = "prod"
const LogListSchemaJsonOperatorsElemLogsElemLogTypeTest LogListSchemaJsonOperatorsElemLogsElemLogType = "test"

type LogListSchemaJsonOperatorsElemLogsElemPreviousOperatorsElem struct {
	// The time at which this operator stopped operating this log.
	EndTime string `json:"end_time"`

	// Name corresponds to the JSON schema field "name".
	Name string `json:"name"`
}

type LogListSchemaJsonOperatorsElemLogsElemState struct {
	// Pending corresponds to the JSON schema field "pending".
	Pending *State `json:"pending,omitempty"`

	// Qualified corresponds to the JSON schema field "qualified".
	Qualified *State `json:"qualified,omitempty"`

	// Readonly corresponds to the JSON schema field "readonly".
	Readonly interface{} `json:"readonly,omitempty"`

	// Rejected corresponds to the JSON schema field "rejected".
	Rejected *State `json:"rejected,omitempty"`

	// Retired corresponds to the JSON schema field "retired".
	Retired *State `json:"retired,omitempty"`

	// Usable corresponds to the JSON schema field "usable".
	Usable *State `json:"usable,omitempty"`
}

// The log will only accept certificates that expire (have a NotAfter date) between
// these dates.
type LogListSchemaJsonOperatorsElemLogsElemTemporalInterval struct {
	// All certificates must expire before this date.
	EndExclusive string `json:"end_exclusive"`

	// All certificates must expire on this date or later.
	StartInclusive string `json:"start_inclusive"`
}

type State struct {
	// The time at which the log entered this state.
	Timestamp string `json:"timestamp"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *LogListSchemaJsonOperatorsElemLogsElemPreviousOperatorsElem) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["end_time"]; !ok || v == nil {
		return fmt.Errorf("field end_time: required")
	}
	if v, ok := raw["name"]; !ok || v == nil {
		return fmt.Errorf("field name: required")
	}
	type Plain LogListSchemaJsonOperatorsElemLogsElemPreviousOperatorsElem
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = LogListSchemaJsonOperatorsElemLogsElemPreviousOperatorsElem(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *LogListSchemaJsonOperatorsElemLogsElemTemporalInterval) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["end_exclusive"]; !ok || v == nil {
		return fmt.Errorf("field end_exclusive: required")
	}
	if v, ok := raw["start_inclusive"]; !ok || v == nil {
		return fmt.Errorf("field start_inclusive: required")
	}
	type Plain LogListSchemaJsonOperatorsElemLogsElemTemporalInterval
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = LogListSchemaJsonOperatorsElemLogsElemTemporalInterval(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *LogListSchemaJsonOperatorsElemLogsElemLogType) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	var ok bool
	for _, expected := range enumValues_LogListSchemaJsonOperatorsElemLogsElemLogType {
		if reflect.DeepEqual(v, expected) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("invalid value (expected one of %#v): %#v", enumValues_LogListSchemaJsonOperatorsElemLogsElemLogType, v)
	}
	*j = LogListSchemaJsonOperatorsElemLogsElemLogType(v)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *LogListSchemaJsonOperatorsElemLogsElem) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["key"]; !ok || v == nil {
		return fmt.Errorf("field key: required")
	}
	if v, ok := raw["log_id"]; !ok || v == nil {
		return fmt.Errorf("field log_id: required")
	}
	if v, ok := raw["url"]; !ok || v == nil {
		return fmt.Errorf("field url: required")
	}
	type Plain LogListSchemaJsonOperatorsElemLogsElem
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	if v, ok := raw["mmd"]; !ok || v == nil {
		plain.Mmd = 86400
	}
	*j = LogListSchemaJsonOperatorsElemLogsElem(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *State) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["timestamp"]; !ok || v == nil {
		return fmt.Errorf("field timestamp: required")
	}
	type Plain State
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = State(plain)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *LogListSchemaJsonOperatorsElem) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["email"]; !ok || v == nil {
		return fmt.Errorf("field email: required")
	}
	if v, ok := raw["logs"]; !ok || v == nil {
		return fmt.Errorf("field logs: required")
	}
	if v, ok := raw["name"]; !ok || v == nil {
		return fmt.Errorf("field name: required")
	}
	type Plain LogListSchemaJsonOperatorsElem
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = LogListSchemaJsonOperatorsElem(plain)
	return nil
}

var enumValues_LogListSchemaJsonOperatorsElemLogsElemLogType = []interface{}{
	"prod",
	"test",
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *LogListSchemaJson) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["operators"]; !ok || v == nil {
		return fmt.Errorf("field operators: required")
	}
	type Plain LogListSchemaJson
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = LogListSchemaJson(plain)
	return nil
}
