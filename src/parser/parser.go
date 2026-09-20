package parser

import (
	"fmt"
)

type Parser struct {
	tokens []Token
	index  int
}

func NewParser(tokens []Token) *Parser {
	return &Parser{
		tokens: tokens,
		index:  0,
	}
}

// token returns the current token, or nil at EOF.
func (p *Parser) token() *Token {
	if p.index >= len(p.tokens) {
		return nil
	}

	return &p.tokens[p.index]
}

// move advances the parser by n tokens.
func (p *Parser) move(n int) {
	p.index += n
}

func (p *Parser) consumeBody(start, end string) ([]Token, error) {
	startToken := p.token()

	if startToken == nil {
		return nil, fmt.Errorf("expected %q", start)
	}

	if startToken.Val != start {
		return nil, fmt.Errorf(
			"expected %q, got %q",
			start,
			startToken.Val,
		)
	}

	p.move(1)

	tokens := make([]Token, 0)
	level := 1

	for {
		t := p.token()

		if t == nil {
			return nil, fmt.Errorf(
				"unclosed %q",
				start,
			)
		}

		if t.Val == start {
			level++

			tokens = append(tokens, *t)
			p.move(1)

			continue
		}

		if t.Val == end {
			level--

			if level == 0 {
				p.move(1)
				break
			}

			tokens = append(tokens, *t)
			p.move(1)

			continue
		}

		tokens = append(tokens, *t)
		p.move(1)
	}

	return tokens, nil
}

func (p *Parser) parseType() (*Type, error) {
	t := p.token()

	if t == nil {
		return nil, fmt.Errorf("expected identifier")
	}

	if !t.isIdentifier() {
		return nil, fmt.Errorf(
			"line %d, expected identifier, got %q",
			t.LineNo,
			t.Val,
		)
	}

	typIdent := *t

	p.move(1)

	t = p.token()

	if t == nil {
		return nil, fmt.Errorf(
			"line %d, expected '{'",
			typIdent.LineNo,
		)
	}

	if t.Typ != LBRACE {
		return nil, fmt.Errorf(
			"line %d, expected '{', got %q",
			typIdent.LineNo,
			t.Val,
		)
	}

	body, err := p.consumeBody("{", "}")
	if err != nil {
		return nil, err
	}

	fields, err := NewParser(body).parseFields()
	if err != nil {
		return nil, err
	}

	return &Type{
		Name:     typIdent.Val,
		Abstract: false,
		Fields:   fields,
	}, nil
}

// parseFields parses the fields contained inside a type.
func (p *Parser) parseFields() ([]*Field, error) {
	typeFields := make([]*Field, 0)

	for {
		t := p.token()

		if t == nil {
			break
		}

		if t.Val != "required" && t.Val != "optional" {
			return nil, fmt.Errorf(
				"line %d, expected 'required' or 'optional', got %q",
				t.LineNo,
				t.Val,
			)
		}

		required := t.Val == "required"

		p.move(1)

		fieldName := p.token()

		if fieldName == nil || !fieldName.isIdentifier() {
			return nil, fmt.Errorf(
				"line %d, expected field identifier",
				t.LineNo,
			)
		}

		p.move(1)

		fieldType, err := p.parseFieldType()
		if err != nil {
			return nil, err
		}

		newField := &Field{
			Name:     fieldName.Val,
			Required: required,
			Typ:      fieldType,
		}

		semi := p.token()

		if semi == nil {
			return nil, fmt.Errorf("expected ';'")
		}

		if semi.Typ != SEMI {
			return nil, fmt.Errorf(
				"expected ';', got %q",
				semi.Val,
			)
		}

		p.move(1)

		typeFields = append(typeFields, newField)
	}

	return typeFields, nil
}

func (p *Parser) parseFieldType() (string, error) {
	t := p.token()

	if t == nil {
		return "", fmt.Errorf("expected ':'")
	}

	if t.Typ != COLON {
		return "", fmt.Errorf(
			"expected ':', got %q",
			t.Val,
		)
	}

	p.move(1)

	t = p.token()

	if t == nil {
		return "", fmt.Errorf(
			"expected type identifier",
		)
	}

	if t.Typ != IDENT {
		return "", fmt.Errorf(
			"expected type identifier, got %q",
			t.Val,
		)
	}

	p.move(1)

	return t.Val, nil
}

func (p *Parser) Parse() ([]Type, error) {
	result := make([]Type, 0)

	for {
		t := p.token()

		if t == nil {
			return result, nil
		}

		if t.Val == "type" {
			p.move(1)

			typ, err := p.parseType()
			if err != nil {
				return nil, err
			}

			result = append(result, *typ)
			continue
		}

		return nil, fmt.Errorf(
			"unexpected token %#v",
			*t,
		)
	}
}

func Parse(source string) (*Schema, error) {

	l := NewLexer(source)

	tokens, err := l.Lex()

	if err != nil {
		return nil, err
	}

	types, err := NewParser(tokens).Parse()
	if err != nil {
		return nil, err
	}

	return NewSchema(types), nil

}
