package query

import (
	"slices"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/connector/kubernetes"
	"github.com/contember/sonda/internal/shape"
)

var workloadRange = api.TimeRange{From: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)}

func testService(t *testing.T, redact ...string) *Service {
	t.Helper()
	redactor, err := shape.NewRedactor(redact)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{redactor: redactor}
}

func event(kind, name, reason string, last time.Time) kubernetes.Event {
	var e kubernetes.Event
	e.InvolvedObject.Kind, e.InvolvedObject.Name = kind, name
	e.Type, e.Reason, e.Message, e.LastTimestamp, e.FirstTimestamp = "Warning", reason, "token=abc happened", last, last
	return e
}

func replicaSet(name, deployment string, created time.Time, replicas int) kubernetes.ReplicaSet {
	var set kubernetes.ReplicaSet
	set.Metadata.Name, set.Metadata.CreationTimestamp = name, created
	set.Metadata.OwnerReferences = []kubernetes.OwnerReference{{Kind: "Deployment", Name: deployment, Controller: true}}
	set.Status.Replicas = replicas
	return set
}

func TestWorkloadEventsKeepOnlyScopedObjects(t *testing.T) {
	at := workloadRange.From.Add(30 * time.Minute)
	var pod kubernetes.Pod
	pod.Metadata.Name = "engine-api-7d9f-abcde"
	sets := []kubernetes.ReplicaSet{replicaSet("engine-api-7d9f", "engine-api", at, 1)}
	events := []kubernetes.Event{
		event("Pod", "engine-api-7d9f-abcde", "BackOff", at),
		event("Pod", "engine-api-7d9f-zzzzz", "OOMKilling", at.Add(time.Minute)), // replaced pod of the scoped ReplicaSet
		event("ReplicaSet", "engine-api-7d9f", "SuccessfulCreate", at),
		event("Deployment", "engine-api", "ScalingReplicaSet", at),
		event("Pod", "engine-api-7d9f-other-abcde", "BackOff", at),                       // pod of another ReplicaSet with a longer name
		event("Pod", "billing-api-1a2b-abcde", "BackOff", at),                            // another service
		event("Pod", "engine-api-7d9f-abcde", "Old", workloadRange.From.Add(-time.Hour)), // before the range
	}
	got := testService(t, `token=\S+`).workloadEvents(events, []kubernetes.Pod{pod}, sets, workloadRange)
	reasons := make([]string, len(got))
	for i, e := range got {
		reasons[i] = e.Reason
	}
	if want := []string{"OOMKilling", "BackOff", "SuccessfulCreate", "ScalingReplicaSet"}; !slices.Equal(reasons, want) {
		t.Errorf("reasons = %v, want %v", reasons, want)
	}
	if got[0].Message != "[REDACTED] happened" || got[0].Count != 1 {
		t.Errorf("event = %+v", got[0])
	}
}

func TestSummarizeWorkloads(t *testing.T) {
	recent := workloadRange.From.Add(10 * time.Minute)
	w := api.Workloads{
		Pods: []api.Pod{
			{Name: "ok", Phase: "Running", Ready: true, Restarts: 1, Containers: []api.Container{
				{Name: "app", State: "running", LastTermination: &api.Termination{Reason: "Error", ExitCode: 1, Finished: workloadRange.From.Add(-time.Hour)}},
			}},
			{Name: "crash", Phase: "Running", Restarts: 5, Containers: []api.Container{
				{Name: "app", State: "waiting", Reason: "CrashLoopBackOff", LastTermination: &api.Termination{Reason: "OOMKilled", ExitCode: 137, Finished: recent}},
			}},
			{Name: "pending", Phase: "Pending", Containers: []api.Container{{Name: "app", State: "waiting", Reason: "ContainerCreating"}}},
			{Name: "job", Phase: "Succeeded"},
		},
		Rollouts: []api.Rollout{{Name: "new", Replicas: 0}, {Name: "current", Replicas: 2}},
		Events:   []api.WorkloadEvent{{Type: "Warning", Count: 3}, {Type: "Normal", Count: 1}},
	}
	s := summarizeWorkloads(w, workloadRange)
	if s.Pods != 4 || s.Ready != 1 || s.Restarts != 6 || s.Warnings != 3 || s.Rollout == nil || s.Rollout.Name != "current" {
		t.Errorf("summary = %+v", s)
	}
	want := []string{
		"crash: app CrashLoopBackOff; app restarted after OOMKilled (exit 137)",
		"pending: not ready, pending",
	}
	if !slices.Equal(s.Problems, want) {
		t.Errorf("problems = %q, want %q", s.Problems, want)
	}
}

func TestShapeRolloutsNewestFirst(t *testing.T) {
	sets := []kubernetes.ReplicaSet{
		replicaSet("old", "engine-api", workloadRange.From, 0),
		replicaSet("new", "engine-api", workloadRange.To, 2),
	}
	sets[1].Metadata.Annotations = map[string]string{"deployment.kubernetes.io/revision": "7"}
	got := shapeRollouts(sets)
	if got[0].Name != "new" || got[0].Revision != "7" || got[0].Owner != "Deployment/engine-api" || got[0].Images == nil {
		t.Errorf("rollouts = %+v", got)
	}
}
