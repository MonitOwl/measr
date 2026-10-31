package appraisal

import "fmt"

// MaxViolations bounds the number of violations reported per container.
const MaxViolations = 20

// violations collects deduplicated violation messages, bounded to [MaxViolations].
type violations struct {
	seen    map[string]struct{}
	items   []string
	dropped int
}

func (v *violations) addf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if _, ok := v.seen[msg]; ok {
		return
	}
	if v.seen == nil {
		v.seen = make(map[string]struct{})
	}
	v.seen[msg] = struct{}{}

	if len(v.items) >= MaxViolations {
		v.dropped++
		return
	}
	v.items = append(v.items, msg)
}

func (v *violations) list() []string {
	if v.dropped > 0 {
		return append(v.items, fmt.Sprintf("... and %d more", v.dropped))
	}
	return v.items
}
