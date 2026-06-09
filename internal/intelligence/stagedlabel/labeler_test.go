package stagedlabel

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

type recordSink struct{ labels []contract.FeedbackLabel }

func (s *recordSink) Label(l contract.FeedbackLabel) error {
	s.labels = append(s.labels, l)
	return nil
}

const scopeA = contract.ScopeKey("scopeA")

func verdict(srcIP string) (contract.SignalEvent, contract.Verdict) {
	flow := contract.FlowIdentity{SocketCookie: 42}
	if srcIP != "" {
		flow.L7Attributes = map[string]string{contract.AttrSourceAddress: srcIP}
	}
	ev := contract.SignalEvent{
		Flow: flow, Scope: scopeA, Canary: "aws.key", Timestamp: time.Unix(1000, 0),
	}
	v := contract.Verdict{Flow: flow, Scope: scopeA, Tier: contract.TierContain}
	return ev, v
}

func regWith(legit, attacker string) *Registry {
	r := NewRegistry()
	if legit != "" {
		r.Declare(scopeA, netip.MustParseAddr(legit), DispLegit)
	}
	if attacker != "" {
		r.Declare(scopeA, netip.MustParseAddr(attacker), DispAttacker)
	}
	return r
}

func TestLabelerDisabledIsNoOp(t *testing.T) {
	sink := &recordSink{}
	l := NewLabeler(regWith("10.0.1.5", "10.0.1.99"), sink, false) // disabled
	ev, v := verdict("10.0.1.99")
	l.OnVerdict(ev, v)
	if len(sink.labels) != 0 {
		t.Fatalf("disabled labeler emitted %d labels", len(sink.labels))
	}
}

func TestLabelerAttackerIsMalicious(t *testing.T) {
	sink := &recordSink{}
	l := NewLabeler(regWith("10.0.1.5", "10.0.1.99"), sink, true)
	ev, v := verdict("10.0.1.99")
	l.OnVerdict(ev, v)
	if len(sink.labels) != 1 {
		t.Fatalf("want 1 label, got %d", len(sink.labels))
	}
	lab := sink.labels[0]
	if !lab.WasMalicious {
		t.Error("attacker verdict labeled benign")
	}
	if lab.Scope != scopeA || lab.Tier != contract.TierContain {
		t.Errorf("label fields wrong: %+v", lab)
	}
	if len(lab.CanariesTouched) != 1 || lab.CanariesTouched[0] != "aws.key" {
		t.Errorf("canary not attributed: %+v", lab.CanariesTouched)
	}
}

func TestLabelerLegitIsBenign(t *testing.T) {
	sink := &recordSink{}
	l := NewLabeler(regWith("10.0.1.5", "10.0.1.99"), sink, true)
	ev, v := verdict("10.0.1.5")
	l.OnVerdict(ev, v)
	if len(sink.labels) != 1 || sink.labels[0].WasMalicious {
		t.Fatalf("legit verdict not labeled benign: %+v", sink.labels)
	}
}

func TestLabelerUnknownSourceNoLabel(t *testing.T) {
	sink := &recordSink{}
	var undeclared []string
	l := NewLabeler(regWith("10.0.1.5", "10.0.1.99"), sink, true)
	l.OnUndeclared(func(a string) { undeclared = append(undeclared, a) })
	// An address not in the registry → no label (production-safety fail-safe).
	ev, v := verdict("10.0.1.250")
	l.OnVerdict(ev, v)
	if len(sink.labels) != 0 {
		t.Fatalf("undeclared source produced a label: %+v", sink.labels)
	}
	if len(undeclared) != 1 {
		t.Fatalf("undeclared hook not called: %v", undeclared)
	}
}

func TestLabelerNoSourceAddressNoLabel(t *testing.T) {
	sink := &recordSink{}
	l := NewLabeler(regWith("10.0.1.5", "10.0.1.99"), sink, true)
	ev, v := verdict("") // no source address stamped
	l.OnVerdict(ev, v)
	if len(sink.labels) != 0 {
		t.Fatalf("missing source address produced a label: %+v", sink.labels)
	}
}

func TestRegistryLoadJSON(t *testing.T) {
	const doc = `{"scopes":[{"scope":"scopeA","legit":["10.0.1.5","10.0.1.6"],"attacker":["10.0.1.99"]}]}`
	reg, err := LoadRegistry(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Lookup(scopeA, netip.MustParseAddr("10.0.1.5")) != DispLegit {
		t.Error("legit not loaded")
	}
	if reg.Lookup(scopeA, netip.MustParseAddr("10.0.1.99")) != DispAttacker {
		t.Error("attacker not loaded")
	}
	if reg.Lookup(scopeA, netip.MustParseAddr("10.0.1.250")) != DispUnknown {
		t.Error("undeclared should be Unknown")
	}
	atk := reg.AttackerAddrs(scopeA)
	if len(atk) != 1 || atk[0] != netip.MustParseAddr("10.0.1.99") {
		t.Errorf("AttackerAddrs = %v", atk)
	}
}

func TestRegistryLoadRejectsBadAddress(t *testing.T) {
	const doc = `{"scopes":[{"scope":"scopeA","attacker":["not-an-ip"]}]}`
	if _, err := LoadRegistry(strings.NewReader(doc)); err == nil {
		t.Fatal("bad address accepted; must fail loud")
	}
}
