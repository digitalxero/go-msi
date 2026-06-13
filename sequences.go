package msi

import (
	"fmt"
	"sort"
)

// msi_sequences.go — P5 sequencing engine. Resolves each custom action's
// ScheduleAfter/Before/At into a concrete sequence number relative to the
// effective action schedule of a sequence table (base standard actions + the P4
// conditional actions that apply to this package + custom actions already
// placed). The base action lists and the conditional injector are left
// untouched, so files-only packages keep their exact (parity-preserving)
// schedule and custom actions only appear when declared.

// baseActionsForTable returns the static base action list for a sequence table.
func baseActionsForTable(t SequenceTable) []msiSequenceRow {
	switch t {
	case InstallExecuteSequence:
		return msiInstallExecuteActions
	case InstallUISequence:
		return msiInstallUIActions
	case AdminExecuteSequence:
		return msiAdminExecuteActions
	case AdminUISequence:
		return msiAdminUIActions
	case AdvtExecuteSequence:
		return msiAdvtExecuteActions
	}
	return nil
}

// effectiveSchedule builds the action->sequence map for a table: base actions +
// the conditional actions whose trigger fires + RemoveExistingProducts when
// applicable. This mirrors exactly what compileMSIPackage emits, so anchors
// resolve against the real schedule.
func effectiveSchedule(p *msiPackage, t SequenceTable) map[string]int16 {
	m := map[string]int16{}
	for _, a := range baseActionsForTable(t) {
		m[a.action] = a.sequence
	}
	name := string(t)
	for _, ca := range msiConditionalActions {
		if ca.table == name && ca.trigger(p) {
			m[ca.action] = ca.sequence
		}
	}
	if t == InstallExecuteSequence && hasUpgradeRemoveRows(p) {
		m["RemoveExistingProducts"] = majorUpgradeRemoveSequence(p)
	}
	return m
}

// nextHigherSeq returns the smallest sequence value strictly greater than lo, or
// lo+windowSize if there is none (so an action anchored at the table's last
// standard action still has room).
func nextHigherSeq(m map[string]int16, lo int16) int16 {
	hi := int16(-1)
	for _, v := range m {
		if v > lo && (hi == -1 || v < hi) {
			hi = v
		}
	}
	if hi == -1 {
		return lo + 100
	}
	return hi
}

// prevLowerSeq returns the largest sequence value strictly less than hi, or
// hi-windowSize if there is none.
func prevLowerSeq(m map[string]int16, hi int16) int16 {
	lo := int16(-1)
	for _, v := range m {
		if v < hi && v > lo {
			lo = v
		}
	}
	if lo == -1 {
		if hi <= 100 {
			return 0
		}
		return hi - 100
	}
	return lo
}

// resolveSequence computes a concrete sequence number for one schedule. The gap
// CEILING/floor is taken from `base` (the immutable standard+conditional
// schedule) so that several custom actions anchored to the same action stack
// upward (4001, 4002, …) rather than colliding; `used` tracks every occupied
// slot (base values + already-placed custom actions) to keep them distinct. It
// errors (never silently) on a missing anchor or a full gap.
func resolveSequence(base map[string]int16, used map[int16]bool, sched caSchedule) (int16, error) {
	switch sched.rel {
	case caRelAt:
		return sched.sequence, nil

	case caRelAfter:
		lo, ok := base[sched.anchor]
		if !ok {
			return 0, fmt.Errorf("anchor action %q is not scheduled in %s", sched.anchor, sched.table)
		}
		hi := nextHigherSeq(base, lo)
		for s := lo + 1; s < hi; s++ {
			if !used[s] {
				return s, nil
			}
		}
		return 0, fmt.Errorf("no free sequence slot after %q (%d) in %s", sched.anchor, lo, sched.table)

	case caRelBefore:
		hi, ok := base[sched.anchor]
		if !ok {
			return 0, fmt.Errorf("anchor action %q is not scheduled in %s", sched.anchor, sched.table)
		}
		lo := prevLowerSeq(base, hi)
		for s := hi - 1; s > lo; s-- {
			if !used[s] {
				return s, nil
			}
		}
		return 0, fmt.Errorf("no free sequence slot before %q (%d) in %s", sched.anchor, hi, sched.table)
	}
	return 0, fmt.Errorf("unknown schedule relation for %s", sched.table)
}

// scheduleCustomActions places every declared custom action into its target
// sequence table(s). Placements accumulate into the per-table effective map so
// multiple custom actions anchored to the same action get distinct slots.
// Deterministic: custom actions in declaration order, schedules in call order.
func scheduleCustomActions(p *msiPackage, db msiDatabaseBuilder) error {
	if len(p.customActions) == 0 {
		return nil
	}
	// Per table: the immutable base schedule (gap bounds) and the mutable used
	// set (collision avoidance, grows as custom actions are placed).
	bases := map[SequenceTable]map[string]int16{}
	useds := map[SequenceTable]map[int16]bool{}
	get := func(t SequenceTable) (map[string]int16, map[int16]bool) {
		if b, ok := bases[t]; ok {
			return b, useds[t]
		}
		b := effectiveSchedule(p, t)
		u := make(map[int16]bool, len(b))
		for _, v := range b {
			u[v] = true
		}
		bases[t] = b
		useds[t] = u
		return b, u
	}

	for _, ca := range p.customActions {
		for _, sched := range ca.schedules {
			base, used := get(sched.table)
			seq, err := resolveSequence(base, used, sched)
			if err != nil {
				return fmt.Errorf("msi compile: scheduling custom action %q: %w", ca.id, err)
			}
			used[seq] = true // reserve so later custom actions don't collide
			var cond any
			if sched.condition != "" {
				cond = sched.condition
			}
			db.WithSequenceAction(string(sched.table), ca.id, cond, seq)
		}
	}
	return nil
}

// msiSortedActions returns a table's actions sorted by sequence (used by tests
// and potential diagnostics).
func msiSortedActions(m map[string]int16) []string {
	type kv struct {
		action string
		seq    int16
	}
	rows := make([]kv, 0, len(m))
	for a, s := range m {
		rows = append(rows, kv{a, s})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].seq != rows[j].seq {
			return rows[i].seq < rows[j].seq
		}
		return rows[i].action < rows[j].action
	})
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.action
	}
	return out
}
