package groundtruth

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,126}[a-z0-9]$|^[a-z0-9]$`)
	unsafeTextPattern = regexp.MustCompile(`(?i)(authorization[[:space:]]*:|bearer[[:space:]]+|password[[:space:]]*[:=]|token[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=]|secret[[:space:]]*[:=]|private[_-]?key|-----begin|https?://)`)
	ipv4Pattern       = regexp.MustCompile(`(^|[^0-9])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9]|$)`)
	hostnamePattern   = regexp.MustCompile(`(?i)(^|[^a-z0-9])([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z]{2,63}([^a-z0-9]|$)`)
	ipv6Pattern       = regexp.MustCompile(`(?i)(^|[^0-9a-f])([0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}([^0-9a-f]|$)`)
)

func identifier(label, value string) error {
	if !identifierPattern.MatchString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be a bounded lowercase identifier", label)
	}
	return nil
}

func safeText(label, value string) error {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return fmt.Errorf("%s must be non-empty, valid UTF-8, trimmed, and at most 512 bytes", label)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	if unsafeTextPattern.MatchString(value) || ipv4Pattern.MatchString(value) || hostnamePattern.MatchString(value) || ipv6Pattern.MatchString(value) {
		return fmt.Errorf("%s contains payload, credential, locator, or address-like content", label)
	}
	return nil
}

func opaqueReference(label, value, prefix string) error {
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("%s must use the %s prefix", label, prefix)
	}
	digest := strings.TrimPrefix(value, prefix)
	if len(digest) != 64 || digest != strings.ToLower(digest) {
		return fmt.Errorf("%s must contain a lowercase SHA-256 digest", label)
	}
	for _, character := range digest {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return fmt.Errorf("%s must contain a lowercase SHA-256 digest", label)
		}
	}
	return nil
}

func recordID(kind RecordKind, value string) error {
	switch kind {
	case RecordScenario:
		if !strings.HasPrefix(value, "scenario:") || !strings.Contains(value, ":v") {
			return fmt.Errorf("scenario record id is invalid")
		}
	case RecordIntent:
		return opaqueReference("intent record id", value, "intent:sha256:")
	case RecordAction:
		return opaqueReference("action record id", value, "action:sha256:")
	default:
		return fmt.Errorf("unsupported record kind %q", kind)
	}
	return nil
}

func canonicalIdentifiers(label string, values []string, required bool) ([]string, error) {
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%s are required", label)
	}
	if len(values) > maximumConfiguredElements {
		return nil, fmt.Errorf("%s exceed the configured bound", label)
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if err := identifier(label, value); err != nil {
			return nil, err
		}
		if index > 0 && result[index-1] == value {
			return nil, fmt.Errorf("duplicate %s value %q", label, value)
		}
	}
	return result, nil
}

func canonicalOpaqueReferences(label string, values []string, prefix string, required bool) ([]string, error) {
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%s are required", label)
	}
	if len(values) > maximumConfiguredElements {
		return nil, fmt.Errorf("%s exceed the configured bound", label)
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if err := opaqueReference(label, value, prefix); err != nil {
			return nil, err
		}
		if index > 0 && result[index-1] == value {
			return nil, fmt.Errorf("duplicate %s value %q", label, value)
		}
	}
	return result, nil
}
