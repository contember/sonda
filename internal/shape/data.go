package shape

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// RedactJSON redacts every string value of a JSON document. It streams tokens, so keys keep
// the order of the query and numbers keep their exact text. Object keys are not redacted:
// they are field names and aliases, or keys inside JSON column values.
func RedactJSON(r *Redactor, data json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var b bytes.Buffer
	// expectKey is true inside an object where the next token is a key; stack tracks it per level.
	var stack []bool
	needComma := false
	for {
		tok, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		inObject := len(stack) > 0 && stack[len(stack)-1]
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if needComma {
					b.WriteByte(',')
				}
				b.WriteByte(byte(t))
				stack = append(stack, t == '{')
				needComma = false
				continue
			case '}', ']':
				b.WriteByte(byte(t))
				stack = stack[:len(stack)-1]
			}
		default:
			if needComma {
				b.WriteByte(',')
			}
			isKey := inObject && b.Len() > 0 && (b.Bytes()[b.Len()-1] == '{' || b.Bytes()[b.Len()-1] == ',')
			if s, ok := t.(string); ok && !isKey {
				t = r.Redact(s)
			}
			encoded, err := marshal(t)
			if err != nil {
				return nil, err
			}
			b.Write(encoded)
			if isKey {
				b.WriteByte(':')
				needComma = false
				continue
			}
		}
		needComma = true
	}
	return b.Bytes(), nil
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
