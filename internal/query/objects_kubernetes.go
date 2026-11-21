package query

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/connector/kubernetes"
)

const (
	// maxJobs keeps the newest Jobs; CronJobs leave a history of them.
	maxJobs = 20
	// maxConfigMaps bounds the ConfigMaps read by name for one service.
	maxConfigMaps = 20
)

// kubernetesObjects is what the namespace lists return before they are related to the service.
type kubernetesObjects struct {
	pods         []kubernetes.Pod
	deployments  []kubernetes.Deployment
	statefulSets []kubernetes.StatefulSet
	daemonSets   []kubernetes.DaemonSet
	jobs         []kubernetes.Job
	cronJobs     []kubernetes.CronJob
	autoscalers  []kubernetes.HorizontalPodAutoscaler
	budgets      []kubernetes.PodDisruptionBudget
	services     []kubernetes.Service
	slices       []kubernetes.EndpointSlice
	ingresses    []kubernetes.Ingress
	policies     []kubernetes.NetworkPolicy
	applications []kubernetes.Application
}

func (b kubernetesWorkloads) objects(ctx context.Context) (objectState, error) {
	query := "objects " + workloadQuery(b.scope)
	recordQuery(ctx, b.scope.Target, query)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		objects   kubernetesObjects
		truncated bool
		errs      []error
	)
	run := func(read func() (bool, error)) {
		wg.Go(func() {
			cut, err := read()
			mu.Lock()
			defer mu.Unlock()
			truncated = truncated || cut
			if err != nil {
				errs = append(errs, err)
			}
		})
	}
	c, scope := b.client, b.scope
	run(func() (cut bool, err error) { objects.pods, cut, err = c.Pods(ctx, scope); return })
	run(func() (cut bool, err error) { objects.deployments, cut, err = c.Deployments(ctx, scope); return })
	run(func() (cut bool, err error) { objects.statefulSets, cut, err = c.StatefulSets(ctx, scope); return })
	run(func() (cut bool, err error) { objects.daemonSets, cut, err = c.DaemonSets(ctx, scope); return })
	run(func() (cut bool, err error) { objects.jobs, cut, err = c.Jobs(ctx, scope); return })
	run(func() (cut bool, err error) { objects.cronJobs, cut, err = c.CronJobs(ctx, scope); return })
	run(func() (cut bool, err error) {
		objects.autoscalers, cut, err = c.HorizontalPodAutoscalers(ctx, scope)
		return
	})
	run(func() (cut bool, err error) { objects.budgets, cut, err = c.PodDisruptionBudgets(ctx, scope); return })
	run(func() (cut bool, err error) { objects.services, cut, err = c.Services(ctx, scope); return })
	run(func() (cut bool, err error) { objects.slices, cut, err = c.EndpointSlices(ctx, scope); return })
	run(func() (cut bool, err error) { objects.ingresses, cut, err = c.Ingresses(ctx, scope); return })
	run(func() (cut bool, err error) { objects.policies, cut, err = c.NetworkPolicies(ctx, scope); return })
	run(func() (cut bool, err error) { objects.applications, cut, err = c.Applications(ctx); return })
	wg.Wait()
	if len(errs) > 0 {
		return objectState{}, errs[0]
	}

	related := b.s.relateObjects(b.scope.Namespace(), b.scope.Labels(), objects)
	data := related.data
	configMaps, err := b.configMaps(ctx, related.configMaps)
	if err != nil {
		return objectState{}, err
	}
	data.ConfigMaps = configMaps
	return objectState{
		data:      data,
		truncated: truncated || related.truncated || len(related.configMaps) > maxConfigMaps,
		source:    api.SourceRef{Kind: "kubernetes", Query: query},
	}, nil
}

// configMaps reads the referenced ConfigMaps by name, keys only, at most maxConfigMaps.
func (b kubernetesWorkloads) configMaps(ctx context.Context, names []string) ([]api.ConfigMap, error) {
	names = names[:min(len(names), maxConfigMaps)]
	result := make([]api.ConfigMap, len(names))
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			cm, found, err := b.client.ConfigMap(ctx, b.scope, name)
			if err != nil {
				errs[i] = err
				return
			}
			result[i] = api.ConfigMap{Name: name, Missing: !found}
			if found {
				created := cm.Metadata.CreationTimestamp
				result[i].Created = &created
				result[i].Keys = slices.Concat([]string(cm.Data), []string(cm.BinaryData))
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

type relatedObjects struct {
	data api.WorkloadObjects
	// configMaps are the names the service's pod templates reference, sorted.
	configMaps []string
	truncated  bool
}

// relateObjects keeps the objects of the namespace that belong to the service:
//   - controllers whose pod template carries every scope label;
//   - Services whose selector selects one of their pod templates or one of the service's pods;
//   - Ingress rules that route to those Services;
//   - NetworkPolicies and PodDisruptionBudgets whose selector matches those pods;
//   - autoscalers of the controllers;
//   - Argo CD Applications that manage a controller, with only the service's own resources.
func (s *Service) relateObjects(namespace string, scopeLabels map[string]string, o kubernetesObjects) relatedObjects {
	var (
		result    relatedObjects
		templates []map[string]string
		owned     = map[string]bool{}
	)
	carries := func(t kubernetes.PodTemplate) bool {
		for key, value := range scopeLabels {
			if t.Metadata.Labels[key] != value {
				return false
			}
		}
		return true
	}
	var configMaps []string
	add := func(c api.Controller, t kubernetes.PodTemplate) {
		c.Containers = containerSpecs(t)
		result.data.Controllers = append(result.data.Controllers, c)
		templates = append(templates, t.Metadata.Labels)
		owned[c.Kind+"/"+c.Name] = true
		configMaps = append(configMaps, t.ConfigMaps()...)
	}
	for _, d := range o.deployments {
		if !carries(d.Spec.Template) {
			continue
		}
		c := api.Controller{Kind: "Deployment", Name: d.Metadata.Name, Created: d.Metadata.CreationTimestamp,
			Replicas: d.Spec.Replicas, ReadyReplicas: d.Status.ReadyReplicas, UpdatedReplicas: d.Status.UpdatedReplicas,
			AvailableReplicas: d.Status.AvailableReplicas, Paused: d.Spec.Paused, Strategy: d.Spec.Strategy.Type,
			Conditions: s.conditions(d.Status.Conditions)}
		if ru := d.Spec.Strategy.RollingUpdate; ru != nil {
			c.Strategy += fmt.Sprintf(" maxSurge=%s maxUnavailable=%s", ru.MaxSurge, ru.MaxUnavailable)
		}
		add(c, d.Spec.Template)
	}
	for _, d := range o.statefulSets {
		if carries(d.Spec.Template) {
			add(api.Controller{Kind: "StatefulSet", Name: d.Metadata.Name, Created: d.Metadata.CreationTimestamp,
				Replicas: d.Spec.Replicas, ReadyReplicas: d.Status.ReadyReplicas, UpdatedReplicas: d.Status.UpdatedReplicas,
				AvailableReplicas: d.Status.AvailableReplicas, Strategy: d.Spec.UpdateStrategy.Type,
				Conditions: s.conditions(d.Status.Conditions)}, d.Spec.Template)
		}
	}
	for _, d := range o.daemonSets {
		if carries(d.Spec.Template) {
			desired := d.Status.DesiredNumberScheduled
			add(api.Controller{Kind: "DaemonSet", Name: d.Metadata.Name, Created: d.Metadata.CreationTimestamp,
				Replicas: &desired, ReadyReplicas: d.Status.NumberReady, UpdatedReplicas: d.Status.UpdatedNumberScheduled,
				AvailableReplicas: d.Status.NumberAvailable, Strategy: d.Spec.UpdateStrategy.Type,
				Conditions: s.conditions(d.Status.Conditions)}, d.Spec.Template)
		}
	}
	for _, d := range o.cronJobs {
		if carries(d.Spec.JobTemplate.Spec.Template) {
			add(api.Controller{Kind: "CronJob", Name: d.Metadata.Name, Created: d.Metadata.CreationTimestamp,
				Schedule: d.Spec.Schedule, Suspended: d.Spec.Suspend != nil && *d.Spec.Suspend,
				LastSchedule: d.Status.LastScheduleTime, LastSuccess: d.Status.LastSuccessfulTime,
				Active: len(d.Status.Active)}, d.Spec.JobTemplate.Spec.Template)
		}
	}
	jobs := slices.Clone(o.jobs)
	sort.SliceStable(jobs, func(i, j int) bool {
		return jobs[i].Metadata.CreationTimestamp.After(jobs[j].Metadata.CreationTimestamp)
	})
	kept := 0
	for _, d := range jobs {
		if !carries(d.Spec.Template) {
			continue
		}
		if kept == maxJobs {
			result.truncated = true
			break
		}
		kept++
		add(api.Controller{Kind: "Job", Name: d.Metadata.Name, Created: d.Metadata.CreationTimestamp,
			Active: d.Status.Active, Succeeded: d.Status.Succeeded, Failed: d.Status.Failed,
			Started: d.Status.StartTime, Completed: d.Status.CompletionTime,
			Conditions: s.conditions(d.Status.Conditions)}, d.Spec.Template)
	}
	if result.data.Controllers == nil {
		result.data.Controllers = []api.Controller{}
	}
	slices.Sort(configMaps)
	result.configMaps = slices.Compact(configMaps)

	// The label sets of the service's pods: those of the templates and of the running pods,
	// which carry the scope labels by the list's selector.
	podLabels := slices.Clone(templates)
	for _, p := range o.pods {
		podLabels = append(podLabels, p.Metadata.Labels)
	}
	selectsPods := func(selector *kubernetes.LabelSelector) bool {
		return slices.ContainsFunc(podLabels, selector.Matches)
	}

	services := map[string]bool{}
	for _, svc := range o.services {
		if len(svc.Spec.Selector) == 0 || !selectsPods(&kubernetes.LabelSelector{MatchLabels: svc.Spec.Selector}) {
			continue
		}
		services[svc.Metadata.Name] = true
		owned["Service/"+svc.Metadata.Name] = true
		ns := api.NetworkService{Name: svc.Metadata.Name, Type: svc.Spec.Type, Selector: svc.Spec.Selector, Ports: []string{},
			LoadBalancer: loadBalancer(svc.Status.LoadBalancer)}
		for _, p := range svc.Spec.Ports {
			port := fmt.Sprintf("%d→%s/%s", p.Port, p.TargetPort, p.Protocol)
			if p.Name != "" {
				port = p.Name + " " + port
			}
			ns.Ports = append(ns.Ports, port)
		}
		for _, slice := range o.slices {
			if slice.Metadata.Labels[kubernetes.ServiceNameLabel] != svc.Metadata.Name {
				continue
			}
			for _, e := range slice.Endpoints {
				// A nil ready condition means ready, as the EndpointSlice API defines it.
				if e.Conditions.Ready == nil || *e.Conditions.Ready {
					ns.ReadyEndpoints++
				} else {
					ns.NotReadyEndpoints++
				}
			}
		}
		result.data.Services = append(result.data.Services, ns)
	}

	for _, ing := range o.ingresses {
		routed := ingressRules(ing, services)
		if len(routed) == 0 {
			continue
		}
		owned["Ingress/"+ing.Metadata.Name] = true
		out := api.Ingress{Name: ing.Metadata.Name, Rules: routed, Addresses: loadBalancer(ing.Status.LoadBalancer)}
		if ing.Spec.IngressClassName != nil {
			out.Class = *ing.Spec.IngressClassName
		}
		for _, tls := range ing.Spec.TLS {
			out.TLSHosts = append(out.TLSHosts, tls.Hosts...)
		}
		result.data.Ingresses = append(result.data.Ingresses, out)
	}

	for _, p := range o.policies {
		if !selectsPods(&p.Spec.PodSelector) {
			continue
		}
		owned["NetworkPolicy/"+p.Metadata.Name] = true
		out := api.NetworkPolicy{Name: p.Metadata.Name, PolicyTypes: p.Spec.PolicyTypes}
		for _, rule := range p.Spec.Ingress {
			out.Ingress = append(out.Ingress, policyRule("from", rule.From, rule.Ports))
		}
		for _, rule := range p.Spec.Egress {
			out.Egress = append(out.Egress, policyRule("to", rule.To, rule.Ports))
		}
		result.data.NetworkPolicies = append(result.data.NetworkPolicies, out)
	}

	for _, pdb := range o.budgets {
		if !selectsPods(pdb.Spec.Selector) {
			continue
		}
		owned["PodDisruptionBudget/"+pdb.Metadata.Name] = true
		out := api.DisruptionBudget{Name: pdb.Metadata.Name, CurrentHealthy: pdb.Status.CurrentHealthy,
			DesiredHealthy: pdb.Status.DesiredHealthy, ExpectedPods: pdb.Status.ExpectedPods,
			DisruptionsAllowed: pdb.Status.DisruptionsAllowed}
		if pdb.Spec.MinAvailable != nil {
			out.MinAvailable = string(*pdb.Spec.MinAvailable)
		}
		if pdb.Spec.MaxUnavailable != nil {
			out.MaxUnavailable = string(*pdb.Spec.MaxUnavailable)
		}
		result.data.DisruptionBudgets = append(result.data.DisruptionBudgets, out)
	}

	for _, hpa := range o.autoscalers {
		target := hpa.Spec.ScaleTargetRef.Kind + "/" + hpa.Spec.ScaleTargetRef.Name
		if !owned[target] {
			continue
		}
		owned["HorizontalPodAutoscaler/"+hpa.Metadata.Name] = true
		out := api.Autoscaler{Name: hpa.Metadata.Name, Target: target, MaxReplicas: hpa.Spec.MaxReplicas,
			MinReplicas: 1, CurrentReplicas: hpa.Status.CurrentReplicas, DesiredReplicas: hpa.Status.DesiredReplicas,
			LastScale: hpa.Status.LastScaleTime, Metrics: autoscalerMetrics(hpa.Spec.Metrics, hpa.Status.CurrentMetrics),
			Conditions: s.conditions(hpa.Status.Conditions)}
		if hpa.Spec.MinReplicas != nil {
			out.MinReplicas = *hpa.Spec.MinReplicas
		}
		result.data.Autoscalers = append(result.data.Autoscalers, out)
	}
	for _, name := range result.configMaps {
		owned["ConfigMap/"+name] = true
	}

	result.data.Applications = s.applications(namespace, o.applications, result.data.Controllers, owned)
	return result
}

// applications keeps the Argo CD Applications that manage one of the service's controllers and
// lists only the service's own objects among their resources.
func (s *Service) applications(namespace string, apps []kubernetes.Application, controllers []api.Controller, owned map[string]bool) []api.Application {
	controls := map[string]bool{}
	for _, c := range controllers {
		controls[c.Kind+"/"+c.Name] = true
	}
	var result []api.Application
	for _, app := range apps {
		manages := slices.ContainsFunc(app.Status.Resources, func(r kubernetes.AppResource) bool {
			return r.Namespace == namespace && controls[r.Kind+"/"+r.Name]
		})
		if !manages {
			continue
		}
		out := api.Application{Name: app.Metadata.Name, Project: app.Spec.Project, Sync: app.Status.Sync.Status,
			Revision: app.Status.Sync.Revision, Health: app.Status.Health.Status,
			HealthMessage: s.redactor.Redact(app.Status.Health.Message), Reconciled: app.Status.ReconciledAt,
			Resources: []api.AppResource{}}
		if op := app.Status.OperationState; op != nil {
			out.Operation, out.OperationDetail, out.OperationEnded = op.Phase, s.redactor.Redact(op.Message), op.FinishedAt
		}
		for _, c := range app.Status.Conditions {
			out.Conditions = append(out.Conditions, api.ObjectCondition{Type: c.Type, Status: "True", Message: s.redactor.Redact(c.Message), Changed: c.LastTransitionTime})
		}
		for _, r := range app.Status.Resources {
			object := r.Kind + "/" + r.Name
			if r.Namespace != namespace || !owned[object] {
				continue
			}
			resource := api.AppResource{Object: object, Sync: r.Status}
			if r.Health != nil {
				resource.Health = r.Health.Status
			}
			out.Resources = append(out.Resources, resource)
		}
		result = append(result, out)
	}
	return result
}

func (s *Service) conditions(conditions []kubernetes.StatusCondition) []api.ObjectCondition {
	var result []api.ObjectCondition
	for _, c := range conditions {
		result = append(result, api.ObjectCondition{Type: c.Type, Status: c.Status, Reason: c.Reason,
			Message: s.redactor.Redact(c.Message), Changed: c.LastTransitionTime})
	}
	return result
}

// containerSpecs describes the containers of a template. Env holds names only.
func containerSpecs(t kubernetes.PodTemplate) []api.ContainerSpec {
	var result []api.ContainerSpec
	describe := func(c kubernetes.ContainerSpec, init bool) {
		spec := api.ContainerSpec{Name: c.Name, Image: c.Image, Init: init,
			Requests: c.Resources.Requests, Limits: c.Resources.Limits}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				spec.SecretEnv = append(spec.SecretEnv, e.Name)
			} else {
				spec.Env = append(spec.Env, e.Name)
			}
		}
		for _, e := range c.EnvFrom {
			if e.ConfigMapRef != nil {
				spec.EnvFrom = append(spec.EnvFrom, "ConfigMap/"+e.ConfigMapRef.Name)
			}
			if e.SecretRef != nil {
				spec.EnvFrom = append(spec.EnvFrom, "Secret/"+e.SecretRef.Name)
			}
		}
		for _, p := range c.Ports {
			port := fmt.Sprintf("%d/%s", p.ContainerPort, cmpOr(p.Protocol, "TCP"))
			if p.Name != "" {
				port = p.Name + " " + port
			}
			spec.Ports = append(spec.Ports, port)
		}
		probes := map[string]string{}
		for kind, p := range map[string]*kubernetes.Probe{"liveness": c.LivenessProbe, "readiness": c.ReadinessProbe, "startup": c.StartupProbe} {
			if p != nil {
				probes[kind] = probeText(p)
			}
		}
		if len(probes) > 0 {
			spec.Probes = probes
		}
		result = append(result, spec)
	}
	for _, c := range t.Spec.InitContainers {
		describe(c, true)
	}
	for _, c := range t.Spec.Containers {
		describe(c, false)
	}
	return result
}

func cmpOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// probeText describes a probe without an exec probe's command, which can hold secrets.
func probeText(p *kubernetes.Probe) string {
	var check string
	switch {
	case p.HTTPGet != nil:
		check = fmt.Sprintf("http :%s%s", p.HTTPGet.Port, p.HTTPGet.Path)
	case p.TCPSocket != nil:
		check = fmt.Sprintf("tcp :%s", p.TCPSocket.Port)
	case p.GRPC != nil:
		check = fmt.Sprintf("grpc :%d", p.GRPC.Port)
	case p.Exec != nil:
		check = "exec"
	default:
		check = "unknown"
	}
	return fmt.Sprintf("%s delay=%ds period=%ds failures=%d", check, p.InitialDelaySeconds, cmpInt(p.PeriodSeconds, 10), cmpInt(p.FailureThreshold, 3))
}

// cmpInt returns the Kubernetes default for an unset (zero) probe field.
func cmpInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func loadBalancer(lb kubernetes.LoadBalancerStatus) []string {
	var result []string
	for _, i := range lb.Ingress {
		result = append(result, cmpOr(i.Hostname, i.IP))
	}
	return result
}

// ingressRules returns the rules that route to one of services, as "host/path → service:port".
func ingressRules(ing kubernetes.Ingress, services map[string]bool) []string {
	backend := func(b kubernetes.IngressBackend) (string, bool) {
		if b.Service == nil || !services[b.Service.Name] {
			return "", false
		}
		port := b.Service.Port.Name
		if port == "" {
			port = strconv.Itoa(b.Service.Port.Number)
		}
		return b.Service.Name + ":" + port, true
	}
	var rules []string
	if b := ing.Spec.DefaultBackend; b != nil {
		if target, ok := backend(*b); ok {
			rules = append(rules, "default → "+target)
		}
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if target, ok := backend(path.Backend); ok {
				rules = append(rules, cmpOr(rule.Host, "*")+cmpOr(path.Path, "/")+" → "+target)
			}
		}
	}
	return rules
}

// policyRule describes one ingress or egress rule; no peers means all, no ports all ports.
func policyRule(direction string, peers []kubernetes.NetworkPolicyPeer, ports []kubernetes.NetworkPolicyPort) string {
	var from []string
	for _, p := range peers {
		var parts []string
		if p.NamespaceSelector != nil {
			parts = append(parts, "namespaces "+selectorText(p.NamespaceSelector))
		}
		if p.PodSelector != nil {
			parts = append(parts, "pods "+selectorText(p.PodSelector))
		}
		if p.IPBlock != nil {
			block := "ip " + p.IPBlock.CIDR
			if len(p.IPBlock.Except) > 0 {
				block += " except " + strings.Join(p.IPBlock.Except, ",")
			}
			parts = append(parts, block)
		}
		from = append(from, strings.Join(parts, " and "))
	}
	text := direction + " " + cmpOr(strings.Join(from, "; "), "anywhere")
	var portList []string
	for _, p := range ports {
		port := "all"
		if p.Port != nil {
			port = string(*p.Port)
			if p.EndPort != nil {
				port += "-" + strconv.Itoa(*p.EndPort)
			}
		}
		protocol := "TCP"
		if p.Protocol != nil {
			protocol = *p.Protocol
		}
		portList = append(portList, port+"/"+protocol)
	}
	if len(portList) > 0 {
		text += " ports " + strings.Join(portList, ",")
	}
	return text
}

func selectorText(s *kubernetes.LabelSelector) string {
	var parts []string
	for _, key := range slices.Sorted(maps.Keys(s.MatchLabels)) {
		parts = append(parts, key+"="+s.MatchLabels[key])
	}
	for _, e := range s.MatchExpressions {
		parts = append(parts, fmt.Sprintf("%s %s (%s)", e.Key, e.Operator, strings.Join(e.Values, ",")))
	}
	if len(parts) == 0 {
		return "{all}"
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// autoscalerMetrics describes each metric as "name current/target".
func autoscalerMetrics(spec, status []kubernetes.HPAMetric) []string {
	var result []string
	for i, m := range spec {
		var current kubernetes.HPAMetric
		if i < len(status) {
			current = status[i]
		}
		switch {
		case m.Resource != nil:
			var now kubernetes.MetricTarget
			if current.Resource != nil {
				now = current.Resource.Current
			}
			result = append(result, m.Resource.Name+" "+targetText(now)+"/"+targetText(m.Resource.Target))
		case m.ContainerResource != nil:
			var now kubernetes.MetricTarget
			if current.ContainerResource != nil {
				now = current.ContainerResource.Current
			}
			result = append(result, m.ContainerResource.Container+" "+m.ContainerResource.Name+" "+targetText(now)+"/"+targetText(m.ContainerResource.Target))
		default:
			if named, ok := m.Named(); ok {
				var now kubernetes.MetricTarget
				if n, ok := current.Named(); ok {
					now = n.Current
				}
				result = append(result, strings.ToLower(m.Type)+" "+named.Metric.Name+" "+targetText(now)+"/"+targetText(named.Target))
			}
		}
	}
	return result
}

func targetText(t kubernetes.MetricTarget) string {
	switch {
	case t.AverageUtilization != nil:
		return strconv.Itoa(*t.AverageUtilization) + "%"
	case t.AverageValue != "":
		return string(t.AverageValue)
	case t.Value != "":
		return string(t.Value)
	}
	return "?"
}
