package evidence

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// OSCALVersion is the OSCAL release the emitted assessment-results conform to.
// The embedded schema below is NIST's published schema for exactly this version.
const OSCALVersion = "1.1.2"

// oscalSchemaBytes is NIST's OSCAL assessment-results JSON schema (v1.1.2, draft-07),
// bundled so validation runs fully offline. OSCAL is a U.S. Government work in the
// public domain (https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2). The only
// change from the published file is that its internal `$id: "#anchor"` references
// were normalized to equivalent JSON-pointer `$ref`s — a semantics-preserving
// rewrite so the constraints compile identically across validators.
//
//go:embed oscal_assessment-results_schema.json
var oscalSchemaBytes []byte

var (
	oscalSchemaOnce sync.Once
	oscalSchema     *jsonschema.Schema
	oscalSchemaErr  error
)

// oscalSchemaID is the schema's own $id; the resource must be registered under
// it so the schema's internal anchors (e.g. #json-schema-directive) resolve.
const oscalSchemaID = "http://csrc.nist.gov/ns/oscal/1.1.2/oscal-ar-schema.json"

func oscalCompiledSchema() (*jsonschema.Schema, error) {
	oscalSchemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		if err := c.AddResource(oscalSchemaID, bytes.NewReader(oscalSchemaBytes)); err != nil {
			oscalSchemaErr = err
			return
		}
		oscalSchema, oscalSchemaErr = c.Compile(oscalSchemaID)
	})
	return oscalSchema, oscalSchemaErr
}

// ValidateOSCAL checks an OSCAL assessment-results JSON document against the
// embedded NIST OSCAL v1.1.2 schema (structure, required fields, UUID/token
// patterns, and enumerations). It returns a descriptive error on any violation.
func ValidateOSCAL(docJSON []byte) error {
	sch, err := oscalCompiledSchema()
	if err != nil {
		return fmt.Errorf("evidence: loading OSCAL schema: %w", err)
	}
	var doc any
	if err := json.Unmarshal(docJSON, &doc); err != nil {
		return fmt.Errorf("evidence: OSCAL document is not valid JSON: %w", err)
	}
	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("evidence: OSCAL document failed schema validation: %w", err)
	}
	return nil
}
