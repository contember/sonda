package query

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/gqlguard"
	"github.com/contember/sonda/internal/policy"
)

// DataCheck is the result of checking one data binding against its source.
type DataCheck struct {
	Service     string
	Environment string
	Source      string
	// WriteAccess is set when the API key can write. The server refuses to start then.
	WriteAccess bool
	Errors      []string
	Warnings    []string
}

// personalField matches field names that often hold personal data.
var personalField = regexp.MustCompile(`(?i)(e-?mail|phone|birth|address|street|password|token|secret|iban|ssn|passport)`)

// CheckData introspects every data binding. It reports keys that can write, unreachable
// sources, allow-list entities and deny_fields entries that do not exist (a typo there would
// silently leave a field readable), and readable fields with names that suggest personal data.
//
// Bindings are checked in parallel, each with its own timeout, so a hanging engine cannot
// keep the check of another binding from finding a key that can write.
func (s *Service) CheckData(ctx context.Context) []DataCheck {
	scopes := s.authz.ContemberScopes()
	checks := make([]DataCheck, len(scopes))
	var wg sync.WaitGroup
	for i, scope := range scopes {
		wg.Go(func() {
			check := DataCheck{Service: scope.Service(), Environment: scope.Environment(), Source: scope.Source().Name}
			loadCtx, cancel := context.WithTimeout(ctx, schemaLoadTimeout)
			defer cancel()
			schema, err := LoadContemberSchema(loadCtx, s.connectors.Contember[scope.Source().Name], scope)
			if err != nil {
				var writeErr *writeAccessError
				check.WriteAccess = errors.As(err, &writeErr)
				check.Errors = append(check.Errors, errorText(err))
			} else {
				check.Errors, check.Warnings = bindingFindings(schema, scope)
			}
			checks[i] = check
		})
	}
	wg.Wait()
	return checks
}

func bindingFindings(schema *gqlguard.Schema, scope authz.ContemberScope) (errs, warnings []string) {
	for _, entity := range scope.Entities() {
		if !schema.HasEntity(entity) {
			errs = append(errs, fmt.Sprintf("entities: %s does not exist or the role cannot read it", entity))
		}
	}
	for _, deny := range scope.DenyFields() {
		entity, field, _ := strings.Cut(deny, ".")
		if entity == "*" {
			if !slices.ContainsFunc(schema.EntityNames(), func(e string) bool { return schema.HasField(e, field) }) {
				errs = append(errs, fmt.Sprintf("deny_fields: no readable entity has a field %s", field))
			}
		} else if !schema.HasField(entity, field) {
			errs = append(errs, fmt.Sprintf("deny_fields: %s does not exist or the role cannot read it", deny))
		}
	}
	entities, _ := schema.Visible(policy.DataRules(scope, config.DefaultLimits))
	for _, e := range entities {
		for _, f := range e.Fields {
			if f.Target == "" && personalField.MatchString(f.Name) {
				warnings = append(warnings, fmt.Sprintf("%s.%s is readable and may hold personal data; deny it unless agents need it", e.Name, f.Name))
			}
		}
	}
	return errs, warnings
}

func errorText(err error) string {
	if e, ok := apierr.As(err); ok {
		return e.Message
	}
	return err.Error()
}
