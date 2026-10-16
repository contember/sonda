package shape

import (
	"fmt"
	"regexp"
)

const redacted = "[REDACTED]"

type redactRule struct {
	pattern     *regexp.Regexp
	replacement string
}

// defaultRules catch common secret shapes. Redaction reduces risk; it is not a guarantee.
var defaultRules = []redactRule{
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`), "Bearer " + redacted},
	{regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/]{8,}=*`), "Basic " + redacted},
	{regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`), "://" + redacted + "@"},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), redacted},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), redacted},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), redacted},
	{
		regexp.MustCompile(`(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']?)[^\s"'&,;}]+`),
		"${1}" + redacted,
	},
}

type Redactor struct {
	rules []redactRule
}

// NewRedactor combines the default rules with extra patterns from the configuration.
func NewRedactor(extra []string) (*Redactor, error) {
	rules := append([]redactRule(nil), defaultRules...)
	for _, pattern := range extra {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("redact pattern %q: %w", pattern, err)
		}
		rules = append(rules, redactRule{pattern: re, replacement: redacted})
	}
	return &Redactor{rules: rules}, nil
}

func (r *Redactor) Redact(s string) string {
	for _, rule := range r.rules {
		s = rule.pattern.ReplaceAllString(s, rule.replacement)
	}
	return s
}
