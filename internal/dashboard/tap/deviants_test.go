package tap

import (
	"net"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/engine/observebaseline"
)

func devIP4(s string) []byte { return net.ParseIP(s).To4() }

// devRec builds a synthetic captured deviant record with a given SRC IP, recurrence
// count, and peak novelty. The DST is a fixed mesh service; only the SRC drives the
// hunting-surface tier.
func devRec(srcIP string, hit uint64, peak float64) observebaseline.DeviantFlowRecordView {
	return observebaseline.DeviantFlowRecordView{
		SrcIP:           devIP4(srcIP),
		DstIP:           devIP4("127.0.1.4"),
		DstPort:         8004,
		Family:          2, // AF_INET (addrFrom keys on len, not Family)
		IdentityNovelty: 1,
		PeakNovelty:     peak,
		PeakLabel:       "new identity",
		HitCount:        hit,
		FirstSeen:       time.Unix(1700000000, 0).UTC(),
		LastSeen:        time.Unix(1700000100, 0).UTC(),
	}
}

// The hunting surface ranks UNFAMILIAR-src FIRST and DEMOTES (never drops) a declared
// mesh-service source to the LAST tier — a genuinely-novel service-initiated flow is a
// lateral-movement lead, so hiding it would bury the highest-value east-west signal.
func TestRankDeviantRowsDemotesServiceKeepsAllTiers(t *testing.T) {
	res := demoResolver(t)
	recs := []observebaseline.DeviantFlowRecordView{
		devRec("127.0.1.2", 9999, 0.9),  // service (api) — HIGHEST hit, must DEMOTE last, NOT drop
		devRec("10.20.1.101", 100, 0.5), // caller (reporting-worker) — tier 1
		devRec("10.20.1.104", 5, 0.7),   // unknown (careful-mover) — LOWEST hit, must rank FIRST
	}
	rows := rankDeviantRows(recs, res, nil)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (service DEMOTED, not dropped), got %d", len(rows))
	}
	if rows[0].Src.Kind != "unknown" || rows[0].SrcFamiliarity != "unfamiliar" {
		t.Fatalf("row0 = %s/%s, want unknown/unfamiliar (careful-mover ranks first despite lowest hit)", rows[0].Src.Kind, rows[0].SrcFamiliarity)
	}
	if rows[1].Src.Kind != "caller" || rows[1].SrcFamiliarity != "known" {
		t.Fatalf("row1 = %s/%s, want caller/known", rows[1].Src.Kind, rows[1].SrcFamiliarity)
	}
	if rows[2].Src.Kind != "service" || rows[2].SrcFamiliarity != "known" {
		t.Fatalf("row2 = %s/%s, want service/known (demoted LAST, present despite 9999 hits)", rows[2].Src.Kind, rows[2].SrcFamiliarity)
	}
}

// Within a tier the prior tiebreak holds: higher HitCount first.
func TestRankDeviantRowsWithinTierTiebreakByHitCount(t *testing.T) {
	res := demoResolver(t)
	recs := []observebaseline.DeviantFlowRecordView{
		devRec("10.20.1.104", 3, 0.6),  // unknown, low hit
		devRec("10.20.1.105", 40, 0.6), // unknown, high hit (both tier 0)
	}
	rows := rankDeviantRows(recs, res, nil)
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	if rows[0].HitCount != 40 || rows[0].SrcFamiliarity != "unfamiliar" {
		t.Fatalf("within-tier tiebreak: higher hit-count first (got hit=%d fam=%s)", rows[0].HitCount, rows[0].SrcFamiliarity)
	}
}
