package authzen

import (
	"fmt"
	"sort"
	"strings"
)

// OpenFGAExport holds an OpenFGA DSL model and YAML tuple set derived from policy rules.
type OpenFGAExport struct {
	Model  string `json:"model"`
	Tuples string `json:"tuples"`
}

// ToOpenFGA converts allow rules to an OpenFGA DSL model + YAML tuples.
// Deny rules and wildcard-ID rules are emitted as comments — OpenFGA handles
// deny via Conditions (ABAC) and wildcards via type-level grants.
func ToOpenFGA(rules []PolicyRule) OpenFGAExport {
	// Collect: subjectType → set; resourceType → actions → grantee subject types
	subjectTypes := map[string]bool{}
	// resourceType → action → set of subject types
	rtActions := map[string]map[string]map[string]bool{}

	for _, r := range rules {
		if !r.Decision {
			continue
		}
		st := fgaName(r.SubjectType)
		rt := fgaName(r.ResourceType)
		an := fgaName(r.ActionName)
		if st == "" || rt == "" || an == "" {
			continue
		}
		subjectTypes[st] = true
		if rtActions[rt] == nil {
			rtActions[rt] = map[string]map[string]bool{}
		}
		if rtActions[rt][an] == nil {
			rtActions[rt][an] = map[string]bool{}
		}
		rtActions[rt][an][st] = true
	}

	var model strings.Builder
	model.WriteString("model\n  schema 1.1\n\n")

	// Subject-only types (not also a resource type)
	sortedST := sortedKeys(subjectTypes)
	for _, st := range sortedST {
		if _, isResource := rtActions[st]; !isResource {
			model.WriteString(fmt.Sprintf("type %s\n\n", st))
		}
	}

	// Resource types with relations
	sortedRT := sortedKeys(rtActions)
	for _, rt := range sortedRT {
		model.WriteString(fmt.Sprintf("type %s\n  relations\n", rt))
		actions := sortedKeys(rtActions[rt])
		for _, an := range actions {
			grantees := sortedKeys(rtActions[rt][an])
			model.WriteString(fmt.Sprintf("    define %s: [%s]\n", an, strings.Join(grantees, ", ")))
		}
		model.WriteString("\n")
	}

	// Tuples for non-wildcard allow rules
	var tuples strings.Builder
	tuples.WriteString("# OpenFGA Tuples (YAML)\n")
	tuples.WriteString("# Use with: fga tuple import --store-id <id> --file tuples.yaml\n\n")
	for _, r := range rules {
		if !r.Decision {
			tuples.WriteString(fmt.Sprintf("# DENY (use Condition): %s\n", r.Label))
			continue
		}
		st := fgaName(r.SubjectType)
		rt := fgaName(r.ResourceType)
		an := fgaName(r.ActionName)
		if st == "" || rt == "" || an == "" {
			tuples.WriteString(fmt.Sprintf("# Wildcard — handle with type-level grant: %s\n", r.Label))
			continue
		}
		hasSubjectWild := strings.Contains(r.SubjectID, "*")
		hasResourceWild := strings.Contains(r.ResourceID, "*")
		if hasSubjectWild || hasResourceWild {
			tuples.WriteString(fmt.Sprintf("# Wildcard — handle with type-level grant: %s\n", r.Label))
			continue
		}
		tuples.WriteString(fmt.Sprintf("- user: %s:%s\n  relation: %s\n  object: %s:%s\n\n",
			st, r.SubjectID, an, rt, r.ResourceID))
	}

	return OpenFGAExport{Model: model.String(), Tuples: tuples.String()}
}

// ToRego converts policy rules to an OPA Rego policy (rego.v1 syntax).
// The generated policy accepts AuthZEN five-tuple input and returns decision.
func ToRego(rules []PolicyRule) string {
	var sb strings.Builder
	sb.WriteString("package authzen\n\n")
	sb.WriteString("import rego.v1\n\n")
	sb.WriteString("# AuthZEN Authorization API — generated Rego policy\n")
	sb.WriteString("# Input schema:\n")
	sb.WriteString("#   { \"subject\": {\"type\":...,\"id\":...},\n")
	sb.WriteString("#     \"resource\": {\"type\":...,\"id\":...},\n")
	sb.WriteString("#     \"action\": {\"name\":...} }\n\n")
	sb.WriteString("default decision := false\n\n")

	for i, r := range rules {
		verb := "ALLOW"
		if !r.Decision {
			verb = "DENY"
		}
		sb.WriteString(fmt.Sprintf("# Rule %d [priority=%d] — %s — %s\n", i+1, r.Priority, verb, r.Label))
		if r.Decision {
			sb.WriteString("decision := true if {\n")
		} else {
			sb.WriteString("decision := false if {\n")
		}
		writeRegoConditions(&sb, r)
		sb.WriteString("}\n\n")
	}

	return sb.String()
}

func writeRegoConditions(sb *strings.Builder, r PolicyRule) {
	cond := func(field, pattern, inputExpr string) {
		if pattern == "" || pattern == "*" {
			return
		}
		if strings.Contains(pattern, "*") {
			prefix := strings.SplitN(pattern, "*", 2)[0]
			if prefix != "" {
				sb.WriteString(fmt.Sprintf("  startswith(%s, %q)\n", inputExpr, prefix))
			}
		} else {
			sb.WriteString(fmt.Sprintf("  %s == %q\n", inputExpr, pattern))
		}
	}
	cond("subject_type", r.SubjectType, "input.subject.type")
	cond("subject_id", r.SubjectID, "input.subject.id")
	cond("resource_type", r.ResourceType, "input.resource.type")
	cond("resource_id", r.ResourceID, "input.resource.id")
	cond("action_name", r.ActionName, "input.action.name")
}

// fgaName converts a rule field to a valid OpenFGA type/relation name.
// Returns "" for wildcards (can't be a type name).
func fgaName(s string) string {
	if s == "" || s == "*" || strings.Contains(s, "*") {
		return ""
	}
	return strings.NewReplacer("-", "_", ".", "_", "/", "_", ":","_").Replace(s)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
