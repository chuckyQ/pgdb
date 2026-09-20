package delta

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/chuckyQ/pgdb/parser"
)

/*
	Helpers
*/

// GetCloseMatches is a Go approximation of Python's
// difflib.get_close_matches.
//
// It returns up to n strings whose similarity to word
// is above cutoff.
func GetCloseMatches(
	word string,
	possibilities []string,
	n int,
) []string {
	type match struct {
		value string
		score float64
	}

	matches := make([]match, 0)

	for _, possibility := range possibilities {
		score := Similarity(word, possibility)

		if score >= 0.6 {
			matches = append(matches, match{
				value: possibility,
				score: score,
			})
		}
	}

	sort.Slice(matches,
		func(i, j int) bool {
			return matches[i].score > matches[j].score
		},
	)

	if len(matches) > n {
		matches = matches[:n]
	}

	result := make([]string, 0, len(matches))

	for _, m := range matches {
		result = append(result, m.value)
	}

	return result
}

// Similarity calculates a simple normalized edit similarity.
//
// 1.0 = identical
// 0.0 = completely different
func Similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	distance := levenshtein(a, b)

	maxLen := len(a)

	if len(b) > maxLen {
		maxLen = len(b)
	}

	return 1.0 - float64(distance)/float64(maxLen)
}

func levenshtein(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)

	for j := 0; j <= len(b); j++ {
		previous[j] = j
	}

	for i := 1; i <= len(a); i++ {
		current[0] = i

		for j := 1; j <= len(b); j++ {
			cost := 0

			if a[i-1] != b[j-1] {
				cost = 1
			}

			tmp := min(current[j-1]+1, previous[j]+1)
			current[j] = min(tmp, previous[j-1]+cost)

		}

		previous, current = current, previous
	}

	return previous[len(b)]
}

func GetYesNo(prompt string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(prompt)

		resp, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}

		resp = strings.ToLower(
			strings.TrimSpace(resp),
		)

		switch resp {
		case "y":
			return true, nil

		case "n":
			return false, nil

		default:
			fmt.Printf(
				"invalid value %q\n",
				resp,
			)
		}
	}
}

func RemoveString(
	values []string,
	target string,
) []string {
	result := make([]string, 0, len(values))

	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}

	return result
}

func RemoveType(
	values []*parser.Type,
	name string,
) []*parser.Type {
	result := make([]*parser.Type, 0, len(values))

	for _, value := range values {
		if value.Name != name {
			result = append(result, value)
		}
	}

	return result
}

func RemoveField(
	values []*parser.Field,
	target *parser.Field,
) []*parser.Field {
	result := make([]*parser.Field, 0, len(values))

	for _, value := range values {
		if !value.Equal(target) {
			result = append(result, value)
		}
	}

	return result
}
