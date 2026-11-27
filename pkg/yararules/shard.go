package yararules

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/prefilter"
	yara "github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog/log"
)

// RuleShard is one independently compiled subset of the user's rule set.
type RuleShard struct {
	Name       string
	Rules      *yara.Rules
	Profile    prefilter.ShardProfile
	Reportable map[string]bool
	RuleOrder  map[string]int

	poolMu sync.Mutex
	pool   []*yara.Scanner
}

// ShardSet is an immutable set of compiled rule shards plus their prefilter
// metadata. It is safe to use from multiple scans; scanners themselves are
// pooled per shard.
type ShardSet struct {
	Shards     []*RuleShard
	Profiles   []prefilter.ShardProfile
	Classifier *prefilter.Classifier
	RuleOrder  map[string]int
	RuleCount  int
}

// Candidates returns the shard indexes that may match a file.
func (s *ShardSet) Candidates(f prefilter.FileFeatures) []int {
	out := make([]int, 0, len(s.Shards))
	for i := range s.Shards {
		if s.Profiles[i].Matches(f) {
			out = append(out, i)
		}
	}
	return out
}

// AllShards returns every shard index.
func (s *ShardSet) AllShards() []int {
	out := make([]int, len(s.Shards))
	for i := range out {
		out[i] = i
	}
	return out
}

// Shard returns the shard at index i.
func (s *ShardSet) Shard(i int) *RuleShard {
	return s.Shards[i]
}

// NewScanner returns a scanner that can be used by one goroutine at a time.
func (r *RuleShard) NewScanner() (*yara.Scanner, error) {
	r.poolMu.Lock()
	if n := len(r.pool); n > 0 {
		s := r.pool[n-1]
		r.pool = r.pool[:n-1]
		r.poolMu.Unlock()
		return s, nil
	}
	r.poolMu.Unlock()

	s, err := yara.NewScanner(r.Rules)
	if err != nil {
		return nil, err
	}
	s.SetTimeout(1 * time.Minute)
	s.SetFlags(0)
	return s, nil
}

// PutScanner returns a scanner to the shard pool.
func (r *RuleShard) PutScanner(s *yara.Scanner) {
	if s == nil {
		return
	}
	r.poolMu.Lock()
	r.pool = append(r.pool, s)
	r.poolMu.Unlock()
}

// CompileShards partitions the existing rule set and compiles each partition.
// If any partition fails to compile, callers should fall back to the legacy
// single ruleset scanner; partial shards are never used.
func (yr *YaraRules) CompileShards(numShards int, failOnCompileWarning bool) (*ShardSet, error) {
	if numShards <= 1 {
		return nil, fmt.Errorf("rule sharding disabled")
	}
	paths, err := getRuleFiles(yr.RulesPath)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no Yara rule files found")
	}
	profile, err := prefilter.ParseRuleFiles(paths)
	if err != nil {
		return nil, err
	}
	plans := buildShardPlans(profile, numShards)
	if len(plans) == 0 {
		return nil, fmt.Errorf("no rules available for sharding")
	}

	ruleOrder := make(map[string]int, len(profile.Rules))
	for i := range profile.Rules {
		ruleOrder[profile.Rules[i].Name] = profile.Rules[i].Index
	}

	shards := make([]*RuleShard, len(plans))
	errCh := make(chan error, len(plans))
	warnMu := sync.Mutex{}
	var warnings []string
	seenWarnings := make(map[string]bool)
	var wg sync.WaitGroup

	limit := runtime.GOMAXPROCS(0)
	if limit > len(plans) {
		limit = len(plans)
	}
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)

	for i := range plans {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			plan := &plans[i]
			source := buildShardSource(profile.Imports, plan.rules)
			compiled, shardWarnings, err := compileShardSource(plan.name, source)
			if err != nil {
				errCh <- fmt.Errorf("shard %s: %w", plan.name, err)
				return
			}
			warnMu.Lock()
			for _, warning := range shardWarnings {
				if seenWarnings[warning] {
					continue
				}
				seenWarnings[warning] = true
				warnings = append(warnings, warning)
			}
			warnMu.Unlock()

			shards[i] = &RuleShard{
				Name:       plan.name,
				Rules:      compiled,
				Profile:    plan.profile,
				Reportable: plan.reportable,
				RuleOrder:  ruleOrder,
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}
	for _, shard := range shards {
		if shard == nil {
			return nil, fmt.Errorf("internal error: shard compilation incomplete")
		}
	}
	if len(warnings) > 0 {
		for _, warning := range warnings {
			log.Warn().Str("ruleset", "file").Str("text", warning).Msg("YARA compiler warning in rule shard")
		}
		if failOnCompileWarning {
			return nil, fmt.Errorf("%d YARA compiler warning(s) found in rule shards", len(warnings))
		}
	}

	profiles := make([]prefilter.ShardProfile, len(shards))
	for i, shard := range shards {
		profiles[i] = shard.Profile
	}
	set := &ShardSet{
		Shards:     shards,
		Profiles:   profiles,
		Classifier: prefilter.NewClassifier(profiles),
		RuleOrder:  ruleOrder,
		RuleCount:  len(profile.Rules),
	}
	log.Info().
		Int("groups", len(shards)).
		Int("rules", len(profile.Rules)).
		Int("base_shards", planCount(plans, true)).
		Int("filter_shards", planCount(plans, false)).
		Msg("compiled yara rule shards")
	return set, nil
}

func planCount(plans []shardPlan, base bool) int {
	n := 0
	for i := range plans {
		if plans[i].base == base {
			n++
		}
	}
	return n
}

type shardPlan struct {
	name       string
	base       bool
	rules      []*prefilter.RuleProfile
	reportable map[string]bool
	profile    prefilter.ShardProfile
}

func buildShardPlans(profile *prefilter.RuleSetProfile, numShards int) []shardPlan {
	var baseRules []*prefilter.RuleProfile
	groups := make(map[string][]*prefilter.RuleProfile)
	filterable := 0
	for i := range profile.Rules {
		rule := &profile.Rules[i]
		if rule.Private || rule.Global {
			continue
		}
		if rule.Always() {
			baseRules = append(baseRules, rule)
			continue
		}
		key := filterGroupKey(rule.Gates)
		groups[key] = append(groups[key], rule)
		filterable++
	}

	var plans []shardPlan
	baseCount := numShards
	if baseCount > len(baseRules) {
		baseCount = len(baseRules)
	}
	if baseCount < 1 && len(baseRules) > 0 {
		baseCount = 1
	}
	for i := 0; i < baseCount; i++ {
		plan := shardPlan{name: fmt.Sprintf("base-%d", i), base: true}
		for j := i; j < len(baseRules); j += baseCount {
			plan.rules = append(plan.rules, baseRules[j])
		}
		finishPlan(profile, &plan)
		plans = append(plans, plan)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	target := filterable / numShards
	if target < 1 {
		target = 1
	}
	type unit struct {
		key   string
		rules []*prefilter.RuleProfile
	}
	var units []unit
	planIndex := 0
	for _, key := range keys {
		rules := groups[key]
		parts := (len(rules) + target - 1) / target
		if parts < 1 {
			parts = 1
		}
		for part := 0; part < parts; part++ {
			u := unit{key: fmt.Sprintf("%s#%d", key, part)}
			for i := part; i < len(rules); i += parts {
				u.rules = append(u.rules, rules[i])
			}
			units = append(units, u)
		}
	}
	sort.SliceStable(units, func(i, j int) bool {
		if len(units[i].rules) != len(units[j].rules) {
			return len(units[i].rules) > len(units[j].rules)
		}
		return units[i].key < units[j].key
	})
	maxFilter := numShards * 4
	if maxFilter < 16 {
		maxFilter = 16
	}
	if len(units) > maxFilter {
		keep := units[:maxFilter-1]
		merged := unit{key: "misc"}
		for _, overflow := range units[maxFilter-1:] {
			merged.rules = append(merged.rules, overflow.rules...)
		}
		units = append(keep, merged)
	}
	for _, u := range units {
		if len(u.rules) == 0 {
			continue
		}
		plan := shardPlan{name: fmt.Sprintf("filter-%d", planIndex)}
		planIndex++
		plan.rules = u.rules
		finishPlan(profile, &plan)
		plans = append(plans, plan)
	}
	return plans
}

func filterGroupKey(gates []prefilter.Gate) string {
	if len(gates) == 0 {
		return ""
	}
	allHaveMagic := true
	hasMagic := false
	magicKeys := make([]string, 0, len(gates))
	for _, gate := range gates {
		if len(gate.Magics) > 0 {
			hasMagic = true
		} else {
			allHaveMagic = false
		}
		var b strings.Builder
		for _, magic := range gate.Magics {
			b.WriteString(magicFamilyKey(magic))
			b.WriteByte(',')
		}
		magicKeys = append(magicKeys, b.String())
	}
	if allHaveMagic && len(magicKeys) > 0 {
		sort.Strings(magicKeys)
		return "magic:" + strings.Join(magicKeys, "|")
	}
	if !hasMagic {
		return "nomagic"
	}
	return "mixed"
}

func magicFamilyKey(magic prefilter.MagicRequirement) string {
	b := magic.Bytes
	family := ""
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		family = "pe"
	case len(b) >= 2 && b[0] == 0x7f && b[1] == 'E':
		family = "elf"
	case len(b) >= 4 && string(b[:4]) == "%PDF":
		family = "pdf"
	case len(b) >= 4 && b[0] == 'P' && b[1] == 'K':
		family = "zip"
	case len(b) >= 4 && b[0] == 0xd0 && b[1] == 0xcf:
		family = "ole"
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		family = "gzip"
	case len(b) >= 4 && string(b[:4]) == "Rar!":
		family = "rar"
	case len(b) >= 4 && b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa:
		family = "macho"
	case len(b) >= 4 && b[0] == 0xca && b[1] == 0xfe && b[2] == 0xba && b[3] == 0xbe:
		family = "java"
	}
	if family == "" {
		family = hex.EncodeToString(b)
	}
	if magic.CaseInsensitive {
		family += "/nocase"
	}
	if magic.Wide {
		family += "/wide"
	}
	if magic.Offset != 0 {
		family += fmt.Sprintf("@%d", magic.Offset)
	}
	return family
}

func finishPlan(profile *prefilter.RuleSetProfile, plan *shardPlan) {
	plan.reportable = make(map[string]bool, len(plan.rules))
	for _, rule := range plan.rules {
		plan.reportable[rule.Name] = true
	}

	include := make(map[string]bool)
	var addRule func(*prefilter.RuleProfile)
	addRule = func(rule *prefilter.RuleProfile) {
		if rule == nil || include[rule.Name] {
			return
		}
		include[rule.Name] = true
		for _, dep := range rule.Deps {
			if idx, ok := profile.RuleByName[dep]; ok {
				addRule(&profile.Rules[idx])
			}
		}
	}
	for _, rule := range plan.rules {
		addRule(rule)
	}
	// Global rules gate every rule in a YARA ruleset, so each shard must carry
	// all of them and their dependencies to preserve semantics.
	for i := range profile.Rules {
		if profile.Rules[i].Global {
			addRule(&profile.Rules[i])
		}
	}

	plan.rules = plan.rules[:0]
	for i := range profile.Rules {
		if include[profile.Rules[i].Name] {
			plan.rules = append(plan.rules, &profile.Rules[i])
		}
	}

	gates := make([]prefilter.Gate, 0)
	always := false
	for _, name := range sortedKeys(plan.reportable) {
		idx := profile.RuleByName[name]
		rule := &profile.Rules[idx]
		if rule.Always() {
			always = true
			break
		}
		gates = append(gates, rule.Gates...)
	}
	plan.profile = prefilter.ShardProfile{
		Name:      plan.name,
		Always:    always,
		Gates:     dedupeGates(gates),
		RuleNames: sortedKeys(plan.reportable),
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func gatesKey(gates []prefilter.Gate) string {
	if len(gates) == 0 {
		return ""
	}
	keys := make([]string, 0, len(gates))
	for _, gate := range gates {
		keys = append(keys, gateKey(gate))
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

func gateKey(gate prefilter.Gate) string {
	var b strings.Builder
	for _, magic := range gate.Magics {
		b.WriteString(fmt.Sprintf("%d/%s/%t/%t/", magic.Offset, hex.EncodeToString(magic.Bytes), magic.CaseInsensitive, magic.Wide))
	}
	b.WriteString(fmt.Sprintf("s%d:%d:e%g:%g", gate.MinSize, gate.MaxSize, gate.MinEntropy, gate.MaxEntropy))
	return b.String()
}

func dedupeGates(gates []prefilter.Gate) []prefilter.Gate {
	seen := make(map[string]bool)
	out := make([]prefilter.Gate, 0, len(gates))
	for _, gate := range gates {
		key := gateKey(gate)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, gate)
	}
	return out
}

func buildShardSource(imports []string, rules []*prefilter.RuleProfile) string {
	var b strings.Builder
	for _, imp := range imports {
		b.WriteString(imp)
		b.WriteByte('\n')
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Index < rules[j].Index
	})
	for _, rule := range rules {
		b.WriteString(rule.Source)
		b.WriteString("\n\n")
	}
	return b.String()
}

func compileShardSource(name, source string) (*yara.Rules, []string, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, nil, err
	}
	defer c.Destroy()
	for k, v := range extvars[constants.Filescan] {
		if err := c.DefineVariable(k, v); err != nil {
			return nil, nil, err
		}
	}
	if err := c.AddString(source, name); err != nil {
		return nil, nil, err
	}
	rules, err := c.GetRules()
	if err != nil {
		var details []string
		for _, e := range c.Errors {
			details = append(details, fmt.Sprintf("%s:%d %s", e.Filename, e.Line, e.Text))
		}
		return nil, nil, fmt.Errorf("%v (%s)", err, strings.Join(details, "; "))
	}
	warnings := make([]string, 0, len(c.Warnings))
	for _, w := range c.Warnings {
		warnings = append(warnings, fmt.Sprintf("%s:%d %s", w.Filename, w.Line, w.Text))
	}
	if len(rules.GetRules()) == 0 {
		return nil, nil, fmt.Errorf("no rules compiled")
	}
	return rules, warnings, nil
}
