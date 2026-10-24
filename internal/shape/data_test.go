package shape

import (
	"encoding/json"
	"testing"
)

func TestRedactJSON(t *testing.T) {
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ in, want string }{
		{
			`{"listOrder":[{"title":"x","id":12345678901234567890,"note":"password=hunter2","tags":["a<b",null,true],"empty":{},"list":[]}]}`,
			`{"listOrder":[{"title":"x","id":12345678901234567890,"note":"password=[REDACTED]","tags":["a<b",null,true],"empty":{},"list":[]}]}`,
		},
		{`{"a":{"b":[{"c":"d"},{"e":[1,2]}]},"f":"g"}`, `{"a":{"b":[{"c":"d"},{"e":[1,2]}]},"f":"g"}`},
		{`{"password=hunter2":"v"}`, `{"password=hunter2":"v"}`},
	} {
		got, err := RedactJSON(r, []byte(tc.in))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want || !json.Valid(got) {
			t.Errorf("got  %s\nwant %s", got, tc.want)
		}
	}
}
