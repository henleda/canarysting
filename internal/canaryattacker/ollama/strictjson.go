package ollama

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func rejectDuplicateKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return fmt.Errorf("unterminated object")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return fmt.Errorf("unterminated array")
			}
		default:
			return fmt.Errorf("unexpected delimiter %q", delimiter)
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON token")
		}
		return err
	}
	return nil
}

func rejectNonCanonicalChatKeys(body []byte) error {
	root, err := exactJSONObject(body,
		"model", "created_at", "message", "done", "done_reason", "total_duration", "load_duration",
		"prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration",
	)
	if err != nil {
		return err
	}
	message, err := exactJSONObject(root["message"], "role", "content", "thinking", "images", "tool_calls")
	if err != nil {
		return err
	}
	if _, exists := message["tool_calls"]; !exists {
		return nil
	}
	var calls []json.RawMessage
	if err := json.Unmarshal(message["tool_calls"], &calls); err != nil {
		return err
	}
	for _, rawCall := range calls {
		call, err := exactJSONObject(rawCall, "id", "type", "function")
		if err != nil {
			return err
		}
		if _, err := exactJSONObject(call["function"], "index", "name", "arguments"); err != nil {
			return err
		}
	}
	return nil
}

func rejectNonCanonicalUnloadKeys(body []byte) error {
	_, err := exactJSONObject(body, "model", "created_at", "response", "done", "done_reason")
	return err
}

func exactJSONObject(body []byte, allowedKeys ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("noncanonical object key")
		}
	}
	return object, nil
}
