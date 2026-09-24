// when.go — constrained fact-based guard expressions (PRD §5.5).
//
// Grammar (small, auditable, no free-form code):
//
//	expr     := or
//	or       := and ( "or" and )*
//	and      := unary ( "and" unary )*
//	unary    := "!" unary | primary
//	primary  := comparison | "(" expr ")"
//	comparison := operand op operand
//	op       := "==" | "!=" | "in"
//	operand  := string | number | factref | bool
//	factref  := ident ("." ident)*   (e.g. host.distro, fact.os)
//
// `in` takes a list literal on the right:  x in ['a','b'].
// String literals are single-quoted. Numbers are integers. The only
// identifiers allowed are fact references (dotted) or the boolean literals
// true/false. Anything else is a parse/eval error → the step is skipped with
// a clear reason (fail-closed for guards).
package task

import (
	"fmt"
	"strconv"
	"strings"
)

// WhenEvaluator evaluates guard expressions against live facts.
type WhenEvaluator struct {
	facts map[string]string
	// fileExists is injected so the evaluator can test file predicates without
	// importing the fs package (keeps this package dependency-light).
	fileExists func(path string) bool
}

// NewWhenEvaluator builds an evaluator bound to the given facts.
func NewWhenEvaluator(facts map[string]string) *WhenEvaluator {
	return &WhenEvaluator{facts: facts, fileExists: func(string) bool { return false }}
}

// SetFileExists installs a file-existence predicate (for file.exists guards).
func (w *WhenEvaluator) SetFileExists(f func(path string) bool) {
	if f != nil {
		w.fileExists = f
	}
}

// Eval evaluates the expression; it returns (value, ok). ok=false means the
// expression was a guard (returned a bool); ok=true means it was a scalar.
func (w *WhenEvaluator) Eval(expr string) (bool, error) {
	if strings.TrimSpace(expr) == "" {
		return true, nil // empty guard = always true
	}
	toks, err := tokenize(expr)
	if err != nil {
		return false, err
	}
	p := &parser{toks: toks, facts: w.facts, fileExists: w.fileExists}
	v, err := p.parseOr()
	if err != nil {
		return false, err
	}
	if p.pos != len(p.toks) {
		return false, fmt.Errorf("when: trailing tokens at %q", p.toks[p.pos].text)
	}
	if b, ok := v.(bool); ok {
		return b, nil
	}
	return false, fmt.Errorf("when: expression is not a boolean (got %v)", v)
}

// ---- tokenizer -------------------------------------------------------------

type tokType int

const (
	tkString tokType = iota
	tkNumber
	tkIdent
	tkOp      // ==, !=
	tkIn
	tkNot
	tkAnd
	tkOr
	tkLParen
	tkRParen
	tkLBracket
	tkRBracket
	tkComma
	tkTrue
	tkFalse
)

type token struct {
	typ  tokType
	text string
	val  any // for string/number/bool literals
}

func tokenize(expr string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(expr) {
		c := expr[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '\'' || c == '"':
			quote := c
			j := i + 1
			start := j
			for j < len(expr) && expr[j] != quote {
				if expr[j] == '\\' && j+1 < len(expr) {
					j++
				}
				j++
			}
			if j >= len(expr) {
				return nil, fmt.Errorf("when: unterminated string")
			}
			raw := expr[start:j]
			toks = append(toks, token{typ: tkString, val: unescape(raw), text: raw})
			i = j + 1
		case c == '(' :
			toks = append(toks, token{typ: tkLParen, text: "("})
			i++
		case c == ')':
			toks = append(toks, token{typ: tkRParen, text: ")"})
			i++
		case c == '[':
			toks = append(toks, token{typ: tkLBracket, text: "["})
			i++
		case c == ']':
			toks = append(toks, token{typ: tkRBracket, text: "]"})
			i++
		case c == ',':
			toks = append(toks, token{typ: tkComma, text: ","})
			i++
		case c == '!':
			if i+1 < len(expr) && expr[i+1] == '=' {
				toks = append(toks, token{typ: tkOp, text: "!="})
				i += 2
			} else {
				toks = append(toks, token{typ: tkNot, text: "!"})
				i++
			}
		case c == '=':
			if i+1 < len(expr) && expr[i+1] == '=' {
				toks = append(toks, token{typ: tkOp, text: "=="})
				i += 2
			} else {
				return nil, fmt.Errorf("when: single '=' not allowed (use ==)")
			}
		case c >= '0' && c <= '9':
			j := i
			for j < len(expr) && (expr[j] >= '0' && expr[j] <= '9') {
				j++
			}
			n, _ := strconv.ParseInt(expr[i:j], 10, 64)
			toks = append(toks, token{typ: tkNumber, val: n, text: expr[i:j]})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(expr) && isIdentPart(expr[j]) {
				j++
			}
			word := expr[i:j]
			switch word {
			case "and":
				toks = append(toks, token{typ: tkAnd, text: word})
			case "or":
				toks = append(toks, token{typ: tkOr, text: word})
			case "in":
				toks = append(toks, token{typ: tkIn, text: word})
			case "true":
				toks = append(toks, token{typ: tkTrue, val: true, text: word})
			case "false":
				toks = append(toks, token{typ: tkFalse, val: false, text: word})
			default:
				toks = append(toks, token{typ: tkIdent, text: word})
			}
			i = j
		default:
			return nil, fmt.Errorf("when: unexpected character %q", string(c))
		}
	}
	return toks, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.'
}

func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ---- parser / evaluator (recursive descent) --------------------------------

type parser struct {
	toks       []token
	pos        int
	facts      map[string]string
	fileExists func(string) bool
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}
func (p *parser) next() token {
	t := p.toks[p.pos]
	p.pos++
	return t
}

func (p *parser) parseOr() (any, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.typ != tkOr {
			break
		}
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = asBool(left) || asBool(right)
	}
	return left, nil
}

func (p *parser) parseAnd() (any, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.typ != tkAnd {
			break
		}
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = asBool(left) && asBool(right)
	}
	return left, nil
}

func (p *parser) parseUnary() (any, error) {
	t := p.peek()
	if t == nil {
		return false, nil
	}
	if t.typ == tkNot {
		p.next()
		v, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return !asBool(v), nil
	}
	if t.typ == tkLParen {
		p.next()
		v, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		t2 := p.peek()
		if t2 == nil || t2.typ != tkRParen {
			return nil, fmt.Errorf("when: missing ')'")
		}
		p.next()
		return v, nil
	}
	return p.parseComparison()
}

// parseComparison parses `operand` optionally followed by (op operand | in list).
func (p *parser) parseComparison() (any, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t == nil {
		return left, nil
	}
	switch t.typ {
	case tkOp:
		p.next()
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return compare(t.text, left, right), nil
	case tkIn:
		p.next()
		if p.peek() == nil || p.peek().typ != tkLBracket {
			return nil, fmt.Errorf("when: 'in' requires a list literal [ ... ]")
		}
		p.next()
		var list []any
		for {
			lt := p.peek()
			if lt == nil {
				return nil, fmt.Errorf("when: unterminated list")
			}
			if lt.typ == tkRBracket {
				p.next()
				break
			}
			v, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			list = append(list, v)
			nt := p.peek()
			if nt == nil {
				return nil, fmt.Errorf("when: unterminated list")
			}
			if nt.typ == tkComma {
				p.next()
				continue
			}
			if nt.typ == tkRBracket {
				p.next()
				break
			}
			return nil, fmt.Errorf("when: expected ',' or ']' in list")
		}
		for _, item := range list {
			if equals(left, item) {
				return true, nil
			}
		}
		return false, nil
	default:
		return left, nil
	}
}

// parseOperand reads a single value: string, number, bool, or a fact/file ref.
func (p *parser) parseOperand() (any, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("when: unexpected end of expression")
	}
	switch t.typ {
	case tkString:
		p.next()
		return t.val, nil
	case tkNumber:
		p.next()
		return t.val, nil
	case tkTrue:
		p.next()
		return true, nil
	case tkFalse:
		p.next()
		return false, nil
	case tkIdent:
		p.next()
		// file.exists('path') predicate.
		if t.text == "file" || strings.HasPrefix(t.text, "file.") {
			if t.text == "file" {
				// Next token must be the ".exists" continuation captured as an ident
				// containing a dot, OR we treat "file.exists" as one token already.
				// Our tokenizer merges dotted idents, so "file.exists" arrives as
				// one token; handled below.
			}
			return p.parseFilePredicateFrom(t)
		}
		if val, ok := p.facts[t.text]; ok {
			return val, nil
		}
		return nil, fmt.Errorf("when: unknown identifier %q", t.text)
	default:
		return nil, fmt.Errorf("when: unexpected token %q as operand", t.text)
	}
}

// parseFilePredicateFrom evaluates file.exists('path') given the leading
// identifier token (which includes ".exists" because the tokenizer merges
// dotted identifiers).
func (p *parser) parseFilePredicateFrom(lead *token) (any, error) {
	if !strings.Contains(lead.text, "exists") {
		return nil, fmt.Errorf("when: file predicate must be file.exists('path')")
	}
	if p.peek() == nil || p.peek().typ != tkLParen {
		return nil, fmt.Errorf("when: file.exists expects ( 'path' )")
	}
	p.next()
	arg := p.peek()
	if arg == nil || arg.typ != tkString {
		return nil, fmt.Errorf("when: file.exists argument must be a string literal")
	}
	p.next()
	if p.peek() == nil || p.peek().typ != tkRParen {
		return nil, fmt.Errorf("when: file.exists missing ')'")
	}
	p.next()
	path, _ := arg.val.(string)
	if p.fileExists == nil {
		return false, nil
	}
	return p.fileExists(path), nil
}

// ---- helpers ---------------------------------------------------------------

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1" || t == "yes"
	case int64:
		return t != 0
	default:
		return false
	}
}

func equals(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func compare(op string, a, b any) bool {
	switch op {
	case "==":
		return equals(a, b)
	case "!=":
		return !equals(a, b)
	}
	return false
}
