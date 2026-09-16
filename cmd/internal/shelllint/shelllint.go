// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// Package shelllint finds `producer | grep -q ...` in shell scripts that run
// under pipefail.
//
// THE DEFECT. `grep -q` (and -m, -l, -L) exits at its first match. If the
// producer is still writing, it dies of SIGPIPE with status 141, and under
// `set -o pipefail` that 141 is the pipeline's status: a pipeline that MATCHED
// reports failure, so `if producer | grep -q X` takes the not-found branch.
// Whether it fires depends on how much the producer has left to write, so it
// is green almost everywhere and red now and then.
//
// THE FIX keeps the reader from leaving early: `grep -q X <<<"$VAR"` (no pipe),
// or `producer | grep X >/dev/null` (grep reads to the end).
//
// SCOPE. A `.sh` file is in scope when it sets pipefail in code, lives under a
// `lib/` or `_lib/` directory, or is sourced (`source f` / `. f`) by a scanned
// file: a sourced helper runs with its caller's options.
//
// WHAT COUNTS AS A PIPE. A `|` in code: not in a comment, a single-quoted
// string, a heredoc body, or a double-quoted string outside a `$(...)`. `||` is
// not a pipe. A pipe that ends a line continues onto the next. A finding is
// reported at the first physical line of its statement.
package shelllint

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one early-exit grep in a pipe, in a script under pipefail.
type Finding struct {
	File string
	Line int
	Text string
}

// Result is a scan's census and its findings.
type Result struct {
	Files    []string
	InScope  []string
	Findings []Finding
}

type codeChar struct {
	c    byte
	line int
}

var (
	heredocRe  = regexp.MustCompile(`^<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)(['"]?)`)
	pipefailRe = regexp.MustCompile(`(^|\s)set\s+(-[A-Za-z]*\s+)*(-[A-Za-z]*o\s+pipefail|-o\s+pipefail)\b`)
	// A `source` or `.` at the start of a statement, and the *.sh name the rest
	// of that line ends in: `. "$(dirname "$0")/helpers.sh"` names helpers.sh.
	sourceRe   = regexp.MustCompile(`(?m)(?:^|[;&|]|\bthen|\bdo|\belse)[ \t]*(?:source|\.)[ \t]+[^;&|\n]*?([A-Za-z0-9_.-]+\.sh)\b`)
	assignRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	shortOptRe = regexp.MustCompile(`^-[A-Za-z0-9]*[qmlL]`)
)

var earlyExitLong = map[string]bool{
	"--quiet": true, "--silent": true, "--max-count": true,
	"--files-with-matches": true, "--files-without-match": true,
}

var greps = map[string]bool{"grep": true, "egrep": true, "fgrep": true}

// codeOf keeps the characters of a script that are shell code, each with its
// physical line, and blanks comments, single-quoted text, heredoc bodies and
// double-quoted text outside a command substitution.
func codeOf(src string) []codeChar {
	var out []codeChar
	stack := []string{"code"}
	top := func() string { return stack[len(stack)-1] }
	line := 1
	type heredoc struct {
		word  string
		strip bool
	}
	var pending []heredoc
	for i := 0; i < len(src); {
		c := src[i]
		if c == '\n' {
			out = append(out, codeChar{c, line})
			line++
			i++
			for _, h := range pending {
				for i < len(src) {
					end := strings.IndexByte(src[i:], '\n')
					var text string
					if end < 0 {
						text, i = src[i:], len(src)
					} else {
						text, i = src[i:i+end], i+end+1
					}
					line++
					if h.strip {
						text = strings.TrimLeft(text, "\t")
					}
					if text == h.word {
						break
					}
				}
			}
			pending = nil
			continue
		}
		if c == '\\' && i+1 < len(src) {
			if src[i+1] == '\n' {
				out = append(out, codeChar{' ', line})
				line++
				i += 2
				continue
			}
			if top() != "dquote" {
				out = append(out, codeChar{' ', line}, codeChar{' ', line})
			}
			i += 2
			continue
		}
		if top() == "dquote" {
			if c == '"' {
				stack = stack[:len(stack)-1]
			} else if c == '$' && i+2 < len(src) && src[i+1] == '(' && src[i+2] != '(' {
				stack = append(stack, "subst")
				out = append(out, codeChar{' ', line}, codeChar{' ', line})
				i += 2
				continue
			}
			i++
			continue
		}
		switch {
		case c == '#' && (i == 0 || strings.ContainsRune(" \t\n;|&(", rune(src[i-1]))):
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case c == '\'':
			end := strings.IndexByte(src[i+1:], '\'')
			var body string
			if end < 0 {
				body, i = src[i+1:], len(src)
			} else {
				body, i = src[i+1:i+1+end], i+end+2
			}
			line += strings.Count(body, "\n")
			out = append(out, codeChar{' ', line})
			continue
		case c == '"':
			stack = append(stack, "dquote")
			out = append(out, codeChar{' ', line})
			i++
			continue
		case c == '$' && i+2 < len(src) && src[i+1] == '(' && src[i+2] != '(':
			stack = append(stack, "subst")
			out = append(out, codeChar{';', line}, codeChar{' ', line})
			i += 2
			continue
		case c == ')' && top() == "subst":
			stack = stack[:len(stack)-1]
			out = append(out, codeChar{';', line})
			i++
			continue
		case c == '<' && strings.HasPrefix(src[i:], "<<") && !strings.HasPrefix(src[i:], "<<<"):
			if m := heredocRe.FindStringSubmatch(src[i:]); m != nil {
				pending = append(pending, heredoc{word: m[3], strip: m[1] == "-"})
				for k := 0; k < len(m[0]); k++ {
					out = append(out, codeChar{' ', line})
				}
				i += len(m[0])
				continue
			}
		}
		out = append(out, codeChar{c, line})
		i++
	}
	return out
}

func codeText(src string) string {
	chars := codeOf(src)
	b := make([]byte, len(chars))
	for i, ch := range chars {
		b[i] = ch.c
	}
	return string(b)
}

func setsPipefail(src string) bool {
	for _, stmt := range regexp.MustCompile(`[\n;]`).Split(codeText(src), -1) {
		if pipefailRe.MatchString(stmt) {
			return true
		}
	}
	return false
}

func isEarlyExitGrep(words []string) bool {
	k := 0
	for k < len(words) && assignRe.MatchString(words[k]) {
		k++
	}
	if k < len(words) && words[k] == "command" {
		k++
	}
	if k >= len(words) || !greps[words[k]] {
		return false
	}
	for _, w := range words[k+1:] {
		if w == "--" {
			break
		}
		if earlyExitLong[strings.SplitN(w, "=", 2)[0]] {
			return true
		}
		if !strings.HasPrefix(w, "--") && shortOptRe.MatchString(w) {
			return true
		}
	}
	return false
}

// findingLines returns the first physical line of every statement that pipes
// into an early-exit grep.
func findingLines(src string) []int {
	chars := codeOf(src)
	seen := map[int]bool{}
	var lines []int
	stmtLine := 0
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
	for i := 0; i < len(chars); i++ {
		c, line := chars[i].c, chars[i].line
		if stmtLine == 0 && !isSpace(c) {
			stmtLine = line
		}
		if c == '|' && (i+1 >= len(chars) || chars[i+1].c != '|') && (i == 0 || chars[i-1].c != '|') {
			j := i + 1
			if j < len(chars) && chars[j].c == '&' {
				j++
			}
			for j < len(chars) && isSpace(chars[j].c) {
				j++
			}
			var text strings.Builder
			for j < len(chars) && !strings.ContainsRune(";|&\n)", rune(chars[j].c)) {
				text.WriteByte(chars[j].c)
				j++
			}
			if isEarlyExitGrep(strings.Fields(text.String())) {
				at := stmtLine
				if at == 0 {
					at = line
				}
				if !seen[at] {
					seen[at] = true
					lines = append(lines, at)
				}
			}
			continue
		}
		switch c {
		case '\n':
			k := i - 1
			for k >= 0 && chars[k].c == ' ' {
				k--
			}
			if k < 0 || (chars[k].c != '|' && chars[k].c != '&') {
				stmtLine = 0
			}
		case ';':
			stmtLine = 0
		}
	}
	return lines
}

// Scan scans every .sh file under the given paths.
func Scan(paths ...string) (Result, error) {
	var files []string
	for _, p := range paths {
		err := filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".sh") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return Result{}, err
		}
	}
	sort.Strings(files)
	sources := map[string]string{}
	sourced := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return Result{}, err
		}
		sources[f] = string(b)
		for _, m := range sourceRe.FindAllStringSubmatch(string(b), -1) {
			sourced[m[1]] = true
		}
	}
	res := Result{Files: files}
	for _, f := range files {
		inLib := false
		for _, part := range strings.Split(filepath.ToSlash(f), "/") {
			if part == "lib" || part == "_lib" {
				inLib = true
			}
		}
		if !setsPipefail(sources[f]) && !inLib && !sourced[filepath.Base(f)] {
			continue
		}
		res.InScope = append(res.InScope, f)
		physical := strings.Split(sources[f], "\n")
		for _, ln := range findingLines(sources[f]) {
			res.Findings = append(res.Findings, Finding{File: f, Line: ln, Text: strings.TrimSpace(physical[ln-1])})
		}
	}
	return res, nil
}
