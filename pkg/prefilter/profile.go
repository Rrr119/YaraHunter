package prefilter

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// ParseRuleFiles parses .yar/.yara files and profiles the rules for safe
// prefiltering. Includes are expanded. Parsing failures are returned to the
// caller, which should fall back to the unsharded scanner rather than risk a
// false negative.
func ParseRuleFiles(paths []string) (*RuleSetProfile, error) {
	p := &RuleSetProfile{RuleByName: make(map[string]int)}
	seenFiles := make(map[string]bool)
	seenImports := make(map[string]bool)
	seenRules := make(map[string]string)

	var load func(string) error
	load = func(path string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		if seenFiles[abs] {
			return nil
		}
		seenFiles[abs] = true

		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := parseSource(path, src)
		if err != nil {
			return err
		}
		for _, imp := range parsed.imports {
			if seenImports[imp] {
				continue
			}
			seenImports[imp] = true
			p.Imports = append(p.Imports, imp)
		}
		for _, inc := range parsed.includes {
			resolved := resolveInclude(path, inc)
			if resolved == "" {
				return fmt.Errorf("could not resolve include %q from %s", inc, path)
			}
			if err := load(resolved); err != nil {
				return err
			}
		}
		for i := range parsed.rules {
			profile := &parsed.rules[i].profile
			if prev, ok := seenRules[profile.Name]; ok {
				if prev == profile.Source {
					continue
				}
				return fmt.Errorf("duplicate rule %q in %s", profile.Name, path)
			}
			seenRules[profile.Name] = profile.Source
			profile.Index = len(p.Rules)
			p.RuleByName[profile.Name] = profile.Index
			p.Rules = append(p.Rules, *profile)
		}
		return nil
	}

	for _, path := range paths {
		if err := load(path); err != nil {
			return nil, err
		}
	}

	for i := range p.Rules {
		p.Rules[i].Deps = resolveDeps(p.Rules[i].condition, p.RuleByName)
	}
	return p, nil
}

func resolveInclude(fromFile, include string) string {
	if filepath.IsAbs(include) {
		if fileExists(include) {
			return include
		}
		return ""
	}
	candidates := []string{
		filepath.Join(filepath.Dir(fromFile), include),
		include,
	}
	for _, candidate := range candidates {
		if fileExists(candidate) {
			return candidate
		}
	}
	return ""
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

type parsedSource struct {
	imports  []string
	includes []string
	rules    []parsedRule
}

type parsedRule struct {
	profile RuleProfile
	// condition is kept separately so dependency extraction does not have to
	// re-parse the full source.
	condition string
}

func parseSource(path string, src []byte) (*parsedSource, error) {
	out := &parsedSource{}
	for i := 0; i < len(src); {
		i = skipSpaceAndComments(src, i)
		if i >= len(src) {
			break
		}
		if !isIdentStart(src[i]) {
			i++
			continue
		}

		start := i
		word, next := readIdent(src, i)
		switch word {
		case "import":
			i = skipSpaceAndComments(src, next)
			value, after, ok := readQuoted(src, i)
			if !ok {
				return nil, fmt.Errorf("%s: malformed import near byte %d", path, start)
			}
			out.imports = append(out.imports, fmt.Sprintf("import %q", value))
			i = after
		case "include":
			i = skipSpaceAndComments(src, next)
			value, after, ok := readQuoted(src, i)
			if !ok {
				return nil, fmt.Errorf("%s: malformed include near byte %d", path, start)
			}
			out.includes = append(out.includes, value)
			i = after
		case "private", "global":
			ruleStart, name, mods, after, ok := parseRuleHeader(src, start)
			if !ok {
				i = next
				continue
			}
			block, afterBlock, condition, err := parseRuleBlock(src, ruleStart, after)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			out.rules = append(out.rules, makeParsedRule(condition, block, name, mods))
			i = afterBlock
		case "rule":
			ruleStart, name, mods, after, ok := parseRuleHeader(src, start)
			if !ok {
				i = next
				continue
			}
			block, afterBlock, condition, err := parseRuleBlock(src, ruleStart, after)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			out.rules = append(out.rules, makeParsedRule(condition, block, name, mods))
			i = afterBlock
		default:
			i = next
		}
	}
	return out, nil
}

type ruleModifiers struct {
	private bool
	global  bool
}

func parseRuleHeader(src []byte, start int) (ruleStart int, name string, mods ruleModifiers, bodyStart int, ok bool) {
	i := start
	for {
		i = skipSpaceAndComments(src, i)
		if i >= len(src) || !isIdentStart(src[i]) {
			return 0, "", mods, 0, false
		}
		word, next := readIdent(src, i)
		switch word {
		case "private":
			mods.private = true
			i = next
		case "global":
			mods.global = true
			i = next
		case "rule":
			i = skipSpaceAndComments(src, next)
			if i >= len(src) || !isIdentStart(src[i]) {
				return 0, "", mods, 0, false
			}
			name, i = readIdent(src, i)
			i = skipSpaceAndComments(src, i)
			if i < len(src) && src[i] == ':' {
				i = skipSpaceAndComments(src, i+1)
				for i < len(src) && isIdentStart(src[i]) {
					_, i = readIdent(src, i)
					i = skipSpaceAndComments(src, i)
				}
			}
			if i >= len(src) || src[i] != '{' {
				return 0, "", mods, 0, false
			}
			return start, name, mods, i + 1, true
		default:
			return 0, "", mods, 0, false
		}
	}
}

func parseRuleBlock(src []byte, ruleStart, bodyStart int) (string, int, string, error) {
	depth := 1
	i := bodyStart
	inStrings := false
	lastWord := ""
	conditionStart := -1
	for i < len(src) {
		if depth == 1 && isIdentStart(src[i]) {
			word, next := readIdent(src, i)
			after := skipSpaceAndComments(src, next)
			if after < len(src) && src[after] == ':' {
				switch word {
				case "strings":
					inStrings = true
				case "condition":
					inStrings = false
					conditionStart = after + 1
				}
			}
			lastWord = word
			i = next
			continue
		}
		switch src[i] {
		case '"':
			_, after, ok := readQuoted(src, i)
			if !ok {
				return "", 0, "", fmt.Errorf("unterminated string at byte %d", i)
			}
			i = after
			continue
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				i = skipLineComment(src, i)
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				i = skipBlockComment(src, i)
				continue
			}
			if inStrings || lastWord == "matches" || looksLikeRegexStartBytes(src, i) {
				if after, ok := skipRegex(src, i); ok {
					i = after
					continue
				}
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				block := string(src[ruleStart : i+1])
				condition := ""
				if conditionStart >= 0 && conditionStart-ruleStart < len(block) {
					condition = stripComments(strings.TrimSpace(block[conditionStart-ruleStart : len(block)-1]))
				} else {
					condition = extractCondition(block)
				}
				if condition == "" {
					return "", 0, "", fmt.Errorf("rule at byte %d has no condition", ruleStart)
				}
				return block, i + 1, condition, nil
			}
		}
		if !isSpace(src[i]) {
			lastWord = ""
		}
		i++
	}
	return "", 0, "", fmt.Errorf("unterminated rule at byte %d", ruleStart)
}

func makeParsedRule(condition, source, name string, mods ruleModifiers) parsedRule {
	defs := parseStringDefs(source)
	return parsedRule{
		profile: RuleProfile{
			Name:      name,
			Private:   mods.private,
			Global:    mods.global,
			Source:    source,
			Gates:     analyzeCondition(condition, defs),
			condition: condition,
		},
		condition: condition,
	}
}

func extractCondition(ruleSource string) string {
	lower := strings.ToLower(ruleSource)
	idx := strings.Index(lower, "condition:")
	if idx < 0 {
		return ""
	}
	cond := ruleSource[idx+len("condition:"):]
	// Drop the final closing brace of the rule.
	cond = strings.TrimSpace(cond)
	if strings.HasSuffix(cond, "}") {
		cond = strings.TrimSpace(cond[:len(cond)-1])
	}
	return stripComments(cond)
}

func stripComments(s string) string {
	src := []byte(s)
	var b strings.Builder
	for i := 0; i < len(src); {
		if src[i] == '"' {
			start := i
			_, after, ok := readQuoted(src, i)
			if ok {
				b.Write(src[start:after])
				i = after
				continue
			}
		}
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '/' {
			i = skipLineComment(src, i)
			continue
		}
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '*' {
			i = skipBlockComment(src, i)
			continue
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String()
}

func skipSpaceAndComments(src []byte, i int) int {
	for i < len(src) {
		if isSpace(src[i]) {
			i++
			continue
		}
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '/' {
			i = skipLineComment(src, i)
			continue
		}
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '*' {
			i = skipBlockComment(src, i)
			continue
		}
		break
	}
	return i
}

func skipLineComment(src []byte, i int) int {
	for i < len(src) && src[i] != '\n' {
		i++
	}
	return i
}

func skipBlockComment(src []byte, i int) int {
	i += 2
	for i+1 < len(src) {
		if src[i] == '*' && src[i+1] == '/' {
			return i + 2
		}
		i++
	}
	return len(src)
}

func readIdent(src []byte, i int) (string, int) {
	start := i
	for i < len(src) && isIdentPart(src[i]) {
		i++
	}
	return string(src[start:i]), i
}

func isIdentStart(b byte) bool {
	return b == '_' || unicode.IsLetter(rune(b))
}

func isIdentPart(b byte) bool {
	return b == '_' || unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b))
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func readQuoted(src []byte, i int) (string, int, bool) {
	if i >= len(src) || src[i] != '"' {
		return "", i, false
	}
	var b strings.Builder
	i++
	for i < len(src) {
		switch src[i] {
		case '"':
			return b.String(), i + 1, true
		case '\\':
			value, after, ok := readEscape(src, i)
			if !ok {
				return "", i, false
			}
			b.WriteString(value)
			i = after
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return "", i, false
}

func readEscape(src []byte, i int) (string, int, bool) {
	if i+1 >= len(src) {
		return "", i, false
	}
	switch src[i+1] {
	case 'n':
		return "\n", i + 2, true
	case 'r':
		return "\r", i + 2, true
	case 't':
		return "\t", i + 2, true
	case '\\':
		return "\\", i + 2, true
	case '"':
		return "\"", i + 2, true
	case 'x':
		if i+3 < len(src) {
			if n, err := strconv.ParseUint(string(src[i+2:i+4]), 16, 8); err == nil {
				return string([]byte{byte(n)}), i + 4, true
			}
		}
	}
	return string(src[i+1]), i + 2, true
}

// stringDef describes the raw literal associated with a $name in a rule.
type stringDef struct {
	name  string
	gates []Gate
}

func parseStringDefs(ruleSource string) map[string]stringDef {
	defs := make(map[string]stringDef)
	stringsIdx := findSection(ruleSource, "strings")
	if stringsIdx < 0 {
		return defs
	}
	condIdx := findSection(ruleSource, "condition")
	if condIdx < 0 {
		return defs
	}
	section := ruleSource[stringsIdx:condIdx]

	src := []byte(section)
	for i := 0; i < len(src); {
		i = skipSpaceAndComments(src, i)
		if i >= len(src) || src[i] != '$' {
			i++
			continue
		}
		i++
		nameStart := i
		for i < len(src) && isIdentPart(src[i]) {
			i++
		}
		name := string(src[nameStart:i])
		i = skipSpaceAndComments(src, i)
		if i >= len(src) || src[i] != '=' {
			continue
		}
		i = skipSpaceAndComments(src, i+1)
		if i >= len(src) {
			break
		}

		var gates []Gate
		switch src[i] {
		case '"':
			literal, after, ok := readQuoted(src, i)
			if ok {
				mods, modsEnd := readStringModifiers(src, after)
				gates = gatesForTextLiteral(literal, mods)
				i = modsEnd
			}
		case '{':
			hexSrc, after, ok := readBraceBlock(src, i)
			if ok {
				gates = gatesForHexLiteral(hexSrc)
				i = after
			}
		case '/':
			if after, ok := skipRegex(src, i); ok {
				i = after
			}
		}
		if name != "" {
			defs[name] = stringDef{name: name, gates: gates}
		}
	}
	return defs
}

func readStringModifiers(src []byte, i int) (string, int) {
	var mods []string
	for {
		i = skipSpaceAndComments(src, i)
		if i >= len(src) || src[i] == '$' {
			break
		}
		if !isIdentStart(src[i]) {
			break
		}
		word, next := readIdent(src, i)
		if strings.EqualFold(word, "condition") {
			after := skipSpaceAndComments(src, next)
			if after < len(src) && src[after] == ':' {
				break
			}
		}
		mods = append(mods, strings.ToLower(word))
		i = next
	}
	return strings.Join(mods, " "), i
}

func findSection(ruleSource, name string) int {
	src := []byte(ruleSource)
	for i := 0; i < len(src); {
		i = skipSpaceAndComments(src, i)
		if i >= len(src) {
			break
		}
		if src[i] == '"' {
			_, after, ok := readQuoted(src, i)
			if ok {
				i = after
				continue
			}
		}
		if !isIdentStart(src[i]) {
			i++
			continue
		}
		word, next := readIdent(src, i)
		after := skipSpaceAndComments(src, next)
		if strings.EqualFold(word, name) && after < len(src) && src[after] == ':' {
			return after + 1
		}
		i = next
	}
	return -1
}

func readBraceBlock(src []byte, i int) (string, int, bool) {
	if i >= len(src) || src[i] != '{' {
		return "", i, false
	}
	depth := 1
	start := i + 1
	i++
	for i < len(src) {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return string(src[start:i]), i + 1, true
			}
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				i = skipLineComment(src, i)
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				i = skipBlockComment(src, i)
				continue
			}
		}
		i++
	}
	return "", i, false
}

func skipRegex(src []byte, i int) (int, bool) {
	if i >= len(src) || src[i] != '/' {
		return i, false
	}
	i++
	for i < len(src) {
		if src[i] == '\\' {
			i += 2
			continue
		}
		if src[i] == '/' {
			return i + 1, true
		}
		i++
	}
	return i, false
}

func gatesForTextLiteral(literal, mods string) []Gate {
	if strings.Contains(mods, "xor") || strings.Contains(mods, "base64") {
		return nil
	}
	bytesValue := []byte(literal)
	if len(bytesValue) == 0 {
		return nil
	}

	nocase := containsModifier(mods, "nocase")
	wide := containsModifier(mods, "wide")
	ascii := containsModifier(mods, "ascii")
	if !ascii && !wide {
		ascii = true
	}

	var gates []Gate
	if ascii {
		gate := emptyGate()
		gate.Magics = append(gate.Magics, MagicRequirement{
			Name:            "literal",
			Bytes:           append([]byte(nil), bytesValue...),
			CaseInsensitive: nocase,
		})
		gates = append(gates, gate)
	}
	if wide {
		gate := emptyGate()
		gate.Magics = append(gate.Magics, MagicRequirement{
			Name:            "wide-literal",
			Bytes:           append([]byte(nil), bytesValue...),
			CaseInsensitive: nocase,
			Wide:            true,
		})
		gates = append(gates, gate)
	}
	return gates
}

func containsModifier(mods, want string) bool {
	for _, field := range strings.FieldsFunc(mods, func(r rune) bool {
		return !(r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r))
	}) {
		if field == want {
			return true
		}
	}
	return false
}

func gatesForHexLiteral(hexSrc string) []Gate {
	var fixed []byte
	i := 0
	for i < len(hexSrc) {
		for i < len(hexSrc) && isSpace(hexSrc[i]) {
			i++
		}
		if i+1 < len(hexSrc) && hexSrc[i] == '/' && hexSrc[i+1] == '/' {
			for i < len(hexSrc) && hexSrc[i] != '\n' {
				i++
			}
			continue
		}
		if i >= len(hexSrc) {
			break
		}
		if hexSrc[i] == '(' || hexSrc[i] == '[' || hexSrc[i] == '|' ||
			hexSrc[i] == '?' || hexSrc[i] == '~' {
			break
		}
		if i+1 >= len(hexSrc) || !isHex(hexSrc[i]) || !isHex(hexSrc[i+1]) {
			break
		}
		value, err := strconv.ParseUint(hexSrc[i:i+2], 16, 8)
		if err != nil {
			break
		}
		fixed = append(fixed, byte(value))
		i += 2
	}
	if len(fixed) == 0 {
		return nil
	}
	gate := emptyGate()
	gate.Magics = append(gate.Magics, MagicRequirement{
		Name:  "hex-literal",
		Bytes: fixed,
	})
	return []Gate{gate}
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func resolveDeps(condition string, known map[string]int) []string {
	var deps []string
	seen := make(map[string]bool)
	for i := 0; i < len(condition); {
		if !isIdentStart(condition[i]) {
			i++
			continue
		}
		token, next := readIdent([]byte(condition), i)
		i = next
		if _, ok := known[token]; ok && !seen[token] {
			seen[token] = true
			deps = append(deps, token)
		}
		if i < len(condition) && condition[i] == '*' {
			// YARA rule sets can use a prefix wildcard. Include every
			// matching rule so the shard still compiles.
			for name := range known {
				if name != token && strings.HasPrefix(name, token) && !seen[name] {
					seen[name] = true
					deps = append(deps, name)
				}
			}
		}
	}
	return deps
}

// analyzeCondition returns the OR-list of necessary constraints implied by a
// condition. An empty result means the rule must always be evaluated.
func analyzeCondition(condition string, defs map[string]stringDef) []Gate {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return nil
	}
	if strings.EqualFold(condition, "false") {
		// A rule that can never match needs no shard.
		return []Gate{deadGate()}
	}
	condition = stripOuterParens(condition)

	if parts := splitTopLevel(condition, "or"); len(parts) > 1 {
		var gates []Gate
		for _, part := range parts {
			partGates := analyzeCondition(part, defs)
			if len(partGates) == 0 {
				return nil
			}
			gates = append(gates, partGates...)
		}
		return gates
	}
	if parts := splitTopLevel(condition, "and"); len(parts) > 1 {
		result := []Gate{emptyGate()}
		for _, part := range parts {
			partGates := analyzeCondition(part, defs)
			if len(partGates) == 0 {
				continue
			}
			var combined []Gate
			for _, left := range result {
				for _, right := range partGates {
					combined = append(combined, left.merge(right))
				}
			}
			if len(combined) > 0 {
				result = combined
			}
		}
		if len(result) == 1 && result[0].Always() {
			return nil
		}
		return result
	}

	return analyzePrimitive(condition, defs)
}

func deadGate() Gate {
	gate := emptyGate()
	gate.MinSize = 1
	gate.MaxSize = 0
	return gate
}

func stripOuterParens(expr string) string {
	for {
		expr = strings.TrimSpace(expr)
		if len(expr) < 2 || expr[0] != '(' || expr[len(expr)-1] != ')' {
			return expr
		}
		depth := 0
		balanced := true
		for i := 0; i < len(expr); i++ {
			switch expr[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(expr)-1 {
					balanced = false
				}
			}
		}
		if !balanced || depth != 0 {
			return expr
		}
		expr = expr[1 : len(expr)-1]
	}
}

// splitTopLevel splits on a lower-case boolean keyword outside parentheses,
// strings and regex literals.
func splitTopLevel(expr, keyword string) []string {
	var parts []string
	depth := 0
	start := 0
	inString := false
	escaped := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '/':
			if i+1 < len(expr) && expr[i+1] != '/' && expr[i+1] != '*' && looksLikeRegexStart(expr, i) {
				if after, ok := skipRegex([]byte(expr), i); ok {
					i = after - 1
					continue
				}
			}
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && i+len(keyword) <= len(expr) &&
				strings.EqualFold(expr[i:i+len(keyword)], keyword) {
				beforeOK := i == 0 || !isIdentPart(expr[i-1])
				after := i + len(keyword)
				afterOK := after == len(expr) || !isIdentPart(expr[after])
				if beforeOK && afterOK {
					parts = append(parts, strings.TrimSpace(expr[start:i]))
					start = after
					i = after - 1
				}
			}
		}
	}
	if len(parts) == 0 {
		return []string{expr}
	}
	parts = append(parts, strings.TrimSpace(expr[start:]))
	return parts
}

func looksLikeRegexStart(expr string, i int) bool {
	return looksLikeRegexStartBytes([]byte(expr), i)
}

func looksLikeRegexStartBytes(expr []byte, i int) bool {
	j := i - 1
	for j >= 0 && isSpace(expr[j]) {
		j--
	}
	if j < 0 {
		return true
	}
	switch expr[j] {
	case '(', ',', '=', ':':
		return true
	}
	k := j
	for k >= 0 && isIdentPart(expr[k]) {
		k--
	}
	return strings.EqualFold(string(expr[k+1:j+1]), "matches")
}

func analyzePrimitive(expr string, defs map[string]stringDef) []Gate {
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "not ") {
		return nil
	}

	if strings.HasSuffix(lower, " at 0") {
		name := strings.TrimSpace(expr[:len(expr)-len(" at 0")])
		if strings.HasPrefix(name, "$") {
			def, ok := defs[strings.TrimPrefix(name, "$")]
			if ok && len(def.gates) > 0 {
				return cloneGates(def.gates)
			}
		}
	}

	if gate, ok := parseFilesizeGate(expr); ok {
		return []Gate{gate}
	}
	if gate, ok := parseEntropyGate(expr); ok {
		return []Gate{gate}
	}
	if gate, ok := parseUintMagic(expr); ok {
		return []Gate{gate}
	}
	if strings.EqualFold(expr, "pe.is_pe") {
		gate := emptyGate()
		gate.Magics = append(gate.Magics, MagicPE)
		return []Gate{gate}
	}
	return nil
}

func cloneGates(in []Gate) []Gate {
	out := make([]Gate, len(in))
	for i, gate := range in {
		out[i] = gate
		out[i].Magics = append([]MagicRequirement{}, gate.Magics...)
	}
	return out
}

func parseFilesizeGate(expr string) (Gate, bool) {
	lower := strings.ToLower(strings.TrimSpace(expr))
	if !strings.HasPrefix(lower, "filesize") {
		return Gate{}, false
	}
	rest := strings.TrimSpace(expr[len("filesize"):])
	op, valueStr, ok := splitComparison(rest)
	if !ok {
		return Gate{}, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(valueStr), 0, 64)
	if err != nil {
		return Gate{}, false
	}
	gate := emptyGate()
	switch op {
	case ">":
		gate.MinSize = value + 1
	case ">=":
		gate.MinSize = value
	case "<":
		gate.MaxSize = value - 1
	case "<=":
		gate.MaxSize = value
	case "==":
		gate.MinSize = value
		gate.MaxSize = value
	default:
		return Gate{}, false
	}
	return gate, true
}

func splitComparison(expr string) (string, string, bool) {
	for _, op := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if idx := strings.Index(expr, op); idx >= 0 {
			return op, expr[idx+len(op):], true
		}
	}
	return "", "", false
}

func parseEntropyGate(expr string) (Gate, bool) {
	lower := strings.ToLower(expr)
	idx := strings.Index(lower, "math.entropy(")
	if idx < 0 || strings.Contains(lower[:idx], "not") {
		return Gate{}, false
	}
	closeRel := strings.Index(expr[idx:], ")")
	if closeRel < 0 {
		return Gate{}, false
	}
	closeIdx := idx + closeRel
	args := strings.ToLower(strings.ReplaceAll(expr[idx+len("math.entropy("):closeIdx], " ", ""))
	if args != "0,filesize" {
		return Gate{}, false
	}
	rest := strings.TrimSpace(expr[closeIdx+1:])
	op, valueStr, ok := splitComparison(rest)
	if !ok {
		return Gate{}, false
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(valueStr), 64)
	if err != nil || value < 0 || value > maxEntropy {
		return Gate{}, false
	}
	gate := emptyGate()
	switch op {
	case ">":
		gate.MinEntropy = value + 1e-9
	case ">=":
		gate.MinEntropy = value
	case "<":
		gate.MaxEntropy = value - 1e-9
	case "<=":
		gate.MaxEntropy = value
	case "==":
		gate.MinEntropy = value
		gate.MaxEntropy = value
	default:
		return Gate{}, false
	}
	return gate, true
}

func parseUintMagic(expr string) (Gate, bool) {
	lower := strings.ToLower(strings.TrimSpace(expr))
	funcs := []struct {
		name         string
		size         int
		littleEndian bool
	}{
		{"uint16(0)", 2, true},
		{"uint32(0)", 4, true},
		{"uint16be(0)", 2, false},
		{"uint32be(0)", 4, false},
		{"uint8(0)", 1, true},
	}
	for _, fn := range funcs {
		if !strings.HasPrefix(lower, fn.name) {
			continue
		}
		rest := strings.TrimSpace(expr[len(fn.name):])
		op, valueStr, ok := splitComparison(rest)
		if !ok || op != "==" {
			return Gate{}, false
		}
		value, err := strconv.ParseUint(strings.TrimSpace(valueStr), 0, 64)
		if err != nil {
			return Gate{}, false
		}
		pattern := make([]byte, fn.size)
		for i := 0; i < fn.size; i++ {
			shift := uint(8 * i)
			if !fn.littleEndian {
				shift = uint(8 * (fn.size - 1 - i))
			}
			pattern[i] = byte(value >> shift)
		}
		gate := emptyGate()
		gate.Magics = append(gate.Magics, MagicRequirement{Name: fn.name, Bytes: pattern})
		return gate, true
	}
	return Gate{}, false
}
