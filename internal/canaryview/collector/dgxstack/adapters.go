package dgxstack

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/canarysting/canarysting/adapters/envoy"
	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/canaryview/model"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/intelligence"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NormalizeCanaryStingInteraction preserves the existing socket-cookie join.
// It does not reinterpret the engine verdict or retain feature values.
func (n *Normalizer) NormalizeCanaryStingInteraction(ctx Context, event intelligence.AdversaryInteractionEvent) (model.Observation, error) {
	if event.ScopeKey == "" || event.ScopeKey != n.policy.Scope.ScopeID() {
		return model.Observation{}, fmt.Errorf("CanarySting event scope does not match canonical scope")
	}
	if event.FlowID == 0 {
		return model.Observation{}, fmt.Errorf("CanarySting interaction requires a nonzero socket cookie")
	}
	subject, err := n.entity("SOCKET_COOKIE", strconv.FormatUint(event.FlowID, 10))
	if err != nil {
		return model.Observation{}, err
	}
	missing := []model.MissingEvidenceKind{}
	var object *model.EntityReference
	if event.CanaryType == "" {
		missing = append(missing, model.MissingObjectIdentity)
	} else {
		value, entityErr := n.entity("CANARY_TYPE", event.CanaryType)
		if entityErr != nil {
			return model.Observation{}, entityErr
		}
		object = &value
	}
	var control *model.ControlIdentity
	if event.Verdict == "" {
		missing = append(missing, model.MissingControlIdentity)
	} else {
		value, controlErr := n.control("CANARYSTING_VERDICT", event.Verdict, strconv.Itoa(event.Tier))
		if controlErr != nil {
			return model.Observation{}, controlErr
		}
		control = &value
	}
	var sourceTime *time.Time
	if event.Timestamp.IsZero() {
		missing = append(missing, model.MissingSourceTimestamp)
	} else {
		value := event.Timestamp.UTC()
		sourceTime = &value
	}
	ctx = n.bindEventKey(ctx, SourceCanarySting,
		strconv.FormatUint(event.FlowID, 10), event.CanaryType, event.Verdict,
		strconv.Itoa(event.Tier), event.Timestamp.UTC().Format(time.RFC3339Nano),
	)
	return n.normalize(ctx, partialReport{
		kind: SourceCanarySting, observationType: "canarysting.canary.interaction",
		sourceTimestamp: sourceTime, subject: &subject, object: object, control: control,
		missing: missing, identityAssurance: model.AssuranceDeclared,
	})
}

// NormalizeObservedTopologyEdge consumes the existing engine snapshot. It does
// not capture, attribute, or persist topology independently of observebaseline.
func (n *Normalizer) NormalizeObservedTopologyEdge(ctx Context, edge observebaseline.TopoEdgeView) (model.Observation, error) {
	if err := validateAddress(edge.Family, edge.SrcIP); err != nil {
		return model.Observation{}, fmt.Errorf("source address: %w", err)
	}
	if err := validateAddress(edge.Family, edge.DstIP); err != nil {
		return model.Observation{}, fmt.Errorf("destination address: %w", err)
	}
	if edge.DstPort == 0 || edge.LastSeen.IsZero() {
		return model.Observation{}, fmt.Errorf("topology edge requires a destination port and last-seen time")
	}
	subject, err := n.entity("NETWORK_ADDRESS", strconv.Itoa(int(edge.Family)), hex.EncodeToString(edge.SrcIP))
	if err != nil {
		return model.Observation{}, err
	}
	object, err := n.entity("SERVICE_ENDPOINT", strconv.Itoa(int(edge.Family)), hex.EncodeToString(edge.DstIP), strconv.Itoa(int(edge.DstPort)))
	if err != nil {
		return model.Observation{}, err
	}
	sourceTime := edge.LastSeen.UTC()
	ctx = n.bindEventKey(ctx, SourceEngine,
		hex.EncodeToString(edge.SrcIP), hex.EncodeToString(edge.DstIP),
		strconv.Itoa(int(edge.DstPort)), edge.LastSeen.UTC().Format(time.RFC3339Nano),
		strconv.FormatUint(edge.FlowCount, 10),
	)
	return n.normalize(ctx, partialReport{
		kind: SourceEngine, observationType: "canarysting.observed-topology.edge",
		sourceTimestamp: &sourceTime, subject: &subject, object: &object,
		missing:           []model.MissingEvidenceKind{model.MissingControlIdentity},
		identityAssurance: model.AssuranceUnverified,
	})
}

// NormalizeKernelFlow consumes the read-only eBPF userspace view. Kernel
// monotonic timestamps are not converted into invented wall-clock source time.
func (n *Normalizer) NormalizeKernelFlow(ctx Context, socketCookie uint64, stats observe.FlowStats) (model.Observation, error) {
	if socketCookie == 0 {
		return model.Observation{}, fmt.Errorf("kernel flow requires a nonzero socket cookie")
	}
	if err := validateAddress(stats.Family, stats.SrcIP[:addressLength(stats.Family)]); err != nil {
		return model.Observation{}, fmt.Errorf("source address: %w", err)
	}
	if err := validateAddress(stats.Family, stats.DstIP[:addressLength(stats.Family)]); err != nil {
		return model.Observation{}, fmt.Errorf("destination address: %w", err)
	}
	if stats.DstPort == 0 || stats.LastSeenNs < stats.FirstSeenNs {
		return model.Observation{}, fmt.Errorf("kernel flow requires a destination port and monotonic timestamps")
	}
	subject, err := n.entity("SOCKET_COOKIE", strconv.FormatUint(socketCookie, 10))
	if err != nil {
		return model.Observation{}, err
	}
	object, err := n.entity("SERVICE_ENDPOINT", strconv.Itoa(int(stats.Family)), hex.EncodeToString(stats.DstIP[:addressLength(stats.Family)]), strconv.Itoa(int(stats.DstPort)))
	if err != nil {
		return model.Observation{}, err
	}
	ctx = n.bindEventKey(ctx, SourceKernel,
		strconv.FormatUint(socketCookie, 10), strconv.FormatUint(stats.FirstSeenNs, 10),
		strconv.FormatUint(stats.LastSeenNs, 10), strconv.FormatUint(stats.TotalPackets(), 10),
		strconv.FormatUint(stats.TotalBytes(), 10),
	)
	return n.normalize(ctx, partialReport{
		kind: SourceKernel, observationType: "kernel.ebpf.flow",
		subject: &subject, object: &object,
		missing:           []model.MissingEvidenceKind{model.MissingSourceTimestamp, model.MissingControlIdentity},
		identityAssurance: model.AssuranceUnverified,
	})
}

// NormalizeEnvoyRequest maps only the socket cookie and pseudonymized resource.
// Method, path, query, headers, and bodies are not retained in the observation.
func (n *Normalizer) NormalizeEnvoyRequest(ctx Context, socketCookie uint64, request envoy.RequestObservation, sourceTimestamp *time.Time) (model.Observation, error) {
	var subject, object *model.EntityReference
	missing := []model.MissingEvidenceKind{model.MissingControlIdentity}
	if socketCookie == 0 {
		missing = append(missing, model.MissingSubjectIdentity)
	} else {
		value, err := n.entity("SOCKET_COOKIE", strconv.FormatUint(socketCookie, 10))
		if err != nil {
			return model.Observation{}, err
		}
		subject = &value
	}
	if request.Path == "" {
		missing = append(missing, model.MissingObjectIdentity)
	} else {
		value, err := n.entity("HTTP_RESOURCE", request.Path)
		if err != nil {
			return model.Observation{}, err
		}
		object = &value
	}
	var sourceTime *time.Time
	if sourceTimestamp == nil || sourceTimestamp.IsZero() {
		missing = append(missing, model.MissingSourceTimestamp)
	} else {
		value := sourceTimestamp.UTC()
		sourceTime = &value
	}
	ctx = n.bindEventKey(ctx, SourceEnvoy,
		strconv.FormatUint(socketCookie, 10), request.Method, request.Path,
		formatOptionalTime(sourceTimestamp),
	)
	return n.normalize(ctx, partialReport{
		kind: SourceEnvoy, observationType: "envoy.http.request",
		sourceTimestamp: sourceTime, subject: subject, object: object, missing: missing,
		identityAssurance: model.AssuranceUnverified,
	})
}

// NormalizeKubernetesObject retains an opaque UID pseudonym and object kind. It
// intentionally excludes names, namespaces, labels, annotations, and managed
// fields from the canonical observation.
func (n *Normalizer) NormalizeKubernetesObject(ctx Context, object metav1.PartialObjectMetadata) (model.Observation, error) {
	if err := boundedRequired("Kubernetes object kind", object.Kind); err != nil {
		return model.Observation{}, err
	}
	var subject *model.EntityReference
	missing := []model.MissingEvidenceKind{model.MissingControlIdentity, model.MissingObjectIdentity}
	if object.UID == "" {
		missing = append(missing, model.MissingSubjectIdentity)
	} else {
		value, err := n.entity("KUBERNETES_OBJECT", string(object.UID), object.APIVersion, object.Kind)
		if err != nil {
			return model.Observation{}, err
		}
		subject = &value
	}
	var sourceTime *time.Time
	if object.CreationTimestamp.IsZero() {
		missing = append(missing, model.MissingSourceTimestamp)
	} else {
		value := object.CreationTimestamp.Time.UTC()
		sourceTime = &value
	}
	ctx = n.bindEventKey(ctx, SourceKubernetes,
		string(object.UID), object.APIVersion, object.Kind, object.ResourceVersion,
	)
	return n.normalize(ctx, partialReport{
		kind: SourceKubernetes, observationType: "kubernetes.object.snapshot",
		sourceTimestamp: sourceTime, subject: subject, missing: missing,
		identityAssurance: model.AssuranceDeclared,
	})
}

// CiliumEndpointReport is the bounded safe subset emitted by the DGX proof.
// M6A owns a versioned Cilium extension/schema and production binding.
type CiliumEndpointReport struct {
	EndpointID uint64
	IdentityID uint32
	ObservedAt time.Time
}

func (n *Normalizer) NormalizeCiliumEndpoint(ctx Context, report CiliumEndpointReport) (model.Observation, error) {
	var subject, object *model.EntityReference
	missing := []model.MissingEvidenceKind{model.MissingControlIdentity}
	if report.IdentityID == 0 {
		missing = append(missing, model.MissingSubjectIdentity)
	} else {
		value, err := n.entity("CILIUM_IDENTITY", strconv.FormatUint(uint64(report.IdentityID), 10))
		if err != nil {
			return model.Observation{}, err
		}
		subject = &value
	}
	if report.EndpointID == 0 {
		missing = append(missing, model.MissingObjectIdentity)
	} else {
		value, err := n.entity("CILIUM_ENDPOINT", strconv.FormatUint(report.EndpointID, 10))
		if err != nil {
			return model.Observation{}, err
		}
		object = &value
	}
	var sourceTime *time.Time
	if report.ObservedAt.IsZero() {
		missing = append(missing, model.MissingSourceTimestamp)
	} else {
		value := report.ObservedAt.UTC()
		sourceTime = &value
	}
	ctx = n.bindEventKey(ctx, SourceCilium,
		strconv.FormatUint(report.EndpointID, 10), strconv.FormatUint(uint64(report.IdentityID), 10),
		report.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	return n.normalize(ctx, partialReport{
		kind: SourceCilium, observationType: "cilium.endpoint.snapshot",
		sourceTimestamp: sourceTime, subject: subject, object: object, missing: missing,
		identityAssurance: model.AssuranceDeclared,
	})
}

// HubbleFlowReport is a deliberately small proof DTO, not a supported Hubble
// schema. It cannot carry payload, HTTP body, header, or socket-cookie fields.
type HubbleFlowReport struct {
	FlowID              string
	SourceIdentity      uint32
	DestinationIdentity uint32
	Verdict             string
	Timestamp           time.Time
}

func (n *Normalizer) NormalizeHubbleFlow(ctx Context, report HubbleFlowReport) (model.Observation, error) {
	if err := boundedRequired("Hubble flow id", report.FlowID); err != nil {
		return model.Observation{}, err
	}
	var subject, object *model.EntityReference
	missing := []model.MissingEvidenceKind{}
	if report.SourceIdentity == 0 {
		missing = append(missing, model.MissingSubjectIdentity)
	} else {
		value, err := n.entity("CILIUM_IDENTITY", strconv.FormatUint(uint64(report.SourceIdentity), 10))
		if err != nil {
			return model.Observation{}, err
		}
		subject = &value
	}
	if report.DestinationIdentity == 0 {
		missing = append(missing, model.MissingObjectIdentity)
	} else {
		value, err := n.entity("CILIUM_IDENTITY", strconv.FormatUint(uint64(report.DestinationIdentity), 10))
		if err != nil {
			return model.Observation{}, err
		}
		object = &value
	}
	var control *model.ControlIdentity
	if report.Verdict == "" {
		missing = append(missing, model.MissingControlIdentity)
	} else {
		value, err := n.control("HUBBLE_VERDICT", report.Verdict)
		if err != nil {
			return model.Observation{}, err
		}
		control = &value
	}
	var sourceTime *time.Time
	if report.Timestamp.IsZero() {
		missing = append(missing, model.MissingSourceTimestamp)
	} else {
		value := report.Timestamp.UTC()
		sourceTime = &value
	}
	ctx = n.bindEventKey(ctx, SourceHubble,
		report.FlowID, strconv.FormatUint(uint64(report.SourceIdentity), 10),
		strconv.FormatUint(uint64(report.DestinationIdentity), 10), report.Verdict,
		report.Timestamp.UTC().Format(time.RFC3339Nano),
	)
	return n.normalize(ctx, partialReport{
		kind: SourceHubble, observationType: "hubble.network.flow",
		sourceTimestamp: sourceTime, subject: subject, object: object, control: control,
		missing: missing, identityAssurance: model.AssuranceDeclared,
	})
}

// NormalizeInventory emits a deliberately partial availability/inventory
// observation from one live DGX source capture. Rich source adapters above are
// covered by focused fixtures; this form lets the proof remain read-only even
// when CanarySting or Hubble is not deployed in the lab.
func (n *Normalizer) NormalizeInventory(ctx Context, kind SourceKind, sourceTimestamp time.Time) (model.Observation, error) {
	var sourceTime *time.Time
	missing := []model.MissingEvidenceKind{
		model.MissingControlIdentity,
		model.MissingSubjectIdentity,
		model.MissingObjectIdentity,
	}
	if sourceTimestamp.IsZero() {
		missing = append(missing, model.MissingSourceTimestamp)
	} else {
		value := sourceTimestamp.UTC()
		sourceTime = &value
	}
	ctx = n.bindEventKey(ctx, kind, sourceTimestamp.UTC().Format(time.RFC3339Nano))
	return n.normalize(ctx, partialReport{
		kind: kind, observationType: string(kind) + ".inventory",
		sourceTimestamp: sourceTime, missing: missing,
		identityAssurance: model.AssuranceUnverified,
	})
}

func addressLength(family uint16) int {
	if family == observe.AFInet {
		return 4
	}
	return 16
}

func validateAddress(family uint16, address []byte) error {
	if family != observe.AFInet && family != observe.AFInet6 {
		return fmt.Errorf("unsupported address family %d", family)
	}
	if len(address) != addressLength(family) {
		return fmt.Errorf("address length %d does not match family %d", len(address), family)
	}
	return nil
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
