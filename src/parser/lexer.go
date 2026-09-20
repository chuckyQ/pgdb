package parser

import (
	"fmt"
	"unicode"
)

type TokenType int

const (
	LBRACE TokenType = iota
	RBRACE
	COLON
	SEMI
	IDENT
	COMMENT
)

type Token struct {
	Val       string
	LineNo    int
	ColOffset int
	Typ       TokenType
}

func (t *Token) isIdentifier() bool {
	return t.Typ == IDENT
}

type Lexer struct {
	txt       string
	colOffset int
	lineno    int
	index     int
}

func NewLexer(txt string) *Lexer {
	return &Lexer{
		txt:       txt,
		colOffset: 0,
		lineno:    1,
		index:     0,
	}
}

var fastSingle = map[byte]TokenType{
	'{': LBRACE,
	'}': RBRACE,
	':': COLON,
	';': SEMI,
}

// move advances the current position.
func (l *Lexer) move(n int) {
	l.index += n
}

// ch returns the current character.
// It returns 0 when the end of the input is reached.
func (l *Lexer) ch() rune {
	if l.index >= len(l.txt) {
		return 0
	}

	return rune(l.txt[l.index])
}

// new creates a new token.
func (l *Lexer) newToken(typ TokenType, val string) Token {
	t := Token{
		Val:       val,
		LineNo:    l.lineno,
		ColOffset: l.colOffset,
		Typ:       typ,
	}

	l.colOffset += len(val)

	return t
}

// lexSingle lexes a single-character token.
func (l *Lexer) lexSingle(typ TokenType, val string) Token {
	t := l.newToken(typ, val)
	l.move(len(val))
	return t
}

// lexIdent lexes an identifier.
func (l *Lexer) lexIdent() Token {
	ch := l.ch()

	if ch == 0 || (!unicode.IsLetter(ch) && ch != '_') {
		panic("invalid identifier")
	}

	buff := []rune{ch}
	l.move(1)

	for {
		ch = l.ch()

		if ch == 0 {
			break
		}

		if ch != '_' && !unicode.IsLetter(ch) && !unicode.IsDigit(ch) {
			break
		}

		buff = append(buff, ch)
		l.move(1)
	}

	return l.newToken(IDENT, string(buff))
}

// lexComment lexes a comment beginning with #.
func (l *Lexer) lexComment() Token {
	ch := l.ch()

	if ch != '#' {
		panic("invalid comment")
	}

	buff := []rune{ch}
	l.move(1)

	for {
		ch = l.ch()

		if ch == 0 || ch == '\n' {
			break
		}

		buff = append(buff, ch)
		l.move(1)
	}

	return l.newToken(COMMENT, string(buff))
}

// Lex returns all tokens from the input.
func (l *Lexer) Lex() ([]Token, error) {
	var tokens []Token

	for {
		ch := l.ch()

		if ch == 0 {
			return tokens, nil
		}

		// Fast path for single-character tokens.
		if typ, ok := fastSingle[byte(ch)]; ok {
			tokens = append(
				tokens,
				l.lexSingle(typ, string(ch)),
			)
			continue
		}

		// Identifier.
		if ch == '_' || unicode.IsLetter(ch) {
			tokens = append(tokens, l.lexIdent())
			continue
		}

		// Comment.
		if ch == '#' {
			tokens = append(tokens, l.lexComment())
			continue
		}

		// New line.
		if ch == '\n' {
			l.lineno++
			l.move(1)
			l.colOffset = 0
			continue
		}

		// Whitespace.
		if unicode.IsSpace(ch) {
			l.move(1)
			l.colOffset++
			continue
		}

		return nil, fmt.Errorf("unexpected %q at line %d, column %d",
			ch,
			l.lineno,
			l.colOffset,
		)
	}
}
